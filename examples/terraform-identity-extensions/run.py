"""Run all remaining built identity managed types with real signed consumers.

Owns one private SQLite controller, a TLS OIDC issuer and a password consumer.
Requires the explicitly enabled real Lambda runtime and current provider models.
"""
import contextlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import threading
import time
from urllib.request import ProxyHandler, Request, build_opener
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from local import (arguments, client, controller, environment, expect_missing,
                   local_endpoint, require, workspace)
import credentials
import federation
import keys
import rotation
import tls

HERE = Path(__file__).resolve().parent
HTTP = build_opener(ProxyHandler({}))
MODULES = {"credentials": credentials, "federation": federation, "keys": keys, "rotation": rotation, "tls": tls}
STORAGE = "ubuntu@sha256:2edbbc5dc405e9612ba3584ce95480277e3eb374407b5505fe26f17df77c7dbc"
TOOLKIT = "nicolaka/netshoot@sha256:47b907d662d139d1e2f22bfe14f4efca1e3f1feed283572f47c970c780c03b61"
RUNTIMES = {
    "x86_64": "public.ecr.aws/lambda/python@sha256:e369e098d9db9eafa3238fe827e4756e2016159908b9426b78e2051c08f647e3",
    "arm64": "public.ecr.aws/lambda/python@sha256:6a1d5d5815a9e754969f1c14f0f6a3ef14a8b094db25e16c1ad5bccc4ee4b99e",
}


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def clock(endpoint, advance=None):
    request = Request(local_endpoint(endpoint) + "/_stackd/clock",
                      data=None if advance is None else json.dumps({"advance": advance}).encode(),
                      headers={"Content-Type": "application/json"})
    with HTTP.open(request, timeout=30) as response:
        return json.load(response)


@contextlib.contextmanager
def ticking(endpoint):
    """Advance explicit manual service time while native provider waiters run."""
    stop, errors = threading.Event(), []

    def advance():
        while not stop.wait(1):
            try:
                clock(endpoint, "5s")
            except Exception as error:
                errors.append(error)
                return

    thread = threading.Thread(target=advance, name="owned-provider-service-clock")
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=35)
        require(not thread.is_alive(), "Owned clock pump did not stop")
        if errors:
            raise RuntimeError("Provider service clock stopped") from errors[0]


def signed(service, endpoint, key, secret, token=None, region="us-east-1"):
    return boto3.Session(aws_access_key_id=key, aws_secret_access_key=secret,
                         aws_session_token=token, region_name=region).client(
        service, endpoint_url=local_endpoint(endpoint),
        config=Config(connect_timeout=3, read_timeout=60, proxies={}, retries={"max_attempts": 0}))


def rejected(call, codes, **kwargs):
    try:
        call(**kwargs)
    except ClientError as error:
        require(error.response["Error"]["Code"] in codes, str(error))
    else:
        raise RuntimeError(f"Unauthorized operation succeeded: {call.__name__}")


def prerequisites(endpoint, root, name):
    organizations, account = client("organizations", endpoint), client("account", endpoint)
    # This controller/DB was just created by local.controller. Never adopt a real
    # or shared account, organization, existing endpoint or mutable native state.
    expect_missing(organizations.describe_organization, {"AWSOrganizationsNotInUseException"})
    before = account.get_region_opt_status(RegionName="ap-southeast-3")["RegionOptStatus"]
    require(before in {"ENABLED", "DISABLED"}, f"Unexpected opt-in before-image: {before}")
    organization = organizations.create_organization(FeatureSet="ALL")["Organization"]
    record = {"organization": organization["Id"], "member": None, "request": None, "region_status": before}
    save(root / "prerequisites.json", record)
    organizations.enable_aws_service_access(ServicePrincipal="iam.amazonaws.com")
    request = organizations.create_account(AccountName=name + "-member", Email=name + "@example.invalid")["CreateAccountStatus"]
    record["request"] = request["Id"]
    save(root / "prerequisites.json", record)
    deadline = time.monotonic() + 90
    while request["State"] == "IN_PROGRESS":
        require(time.monotonic() < deadline, "Owned local member-account provisioning did not complete")
        clock(endpoint, "5s")
        time.sleep(0.1)
        request = organizations.describe_create_account_status(CreateAccountRequestId=request["Id"])["CreateAccountStatus"]
    require(request["State"] == "SUCCEEDED", f"Owned account provisioning failed: {request}")
    record["member"] = request["AccountId"]
    save(root / "prerequisites.json", record)
    return record


def verify_controls(endpoint, out, revision):
    iam, account = client("iam", endpoint), client("account", endpoint)
    enabled = {"RootCredentialsManagement"} | ({"RootSessions"} if revision == "v2" else set())
    features = iam.list_organizations_features()
    require(features["OrganizationId"] == out["organization_id"] and set(features.get("EnabledFeatures", [])) == enabled,
            "Terraform organization root features differ from the current owner")
    operator = signed("sts", endpoint, out["operator_key"], out["operator_secret"])
    arguments = {"TargetPrincipal": out["member_account_id"], "DurationSeconds": 900,
                 "TaskPolicyArn": {"arn": "arn:aws:iam::aws:policy/root-task/IAMAuditRootUserCredentials"}}
    session = operator.assume_root(**arguments)["Credentials"]
    member = signed("iam", endpoint, session["AccessKeyId"], session["SecretAccessKey"], session["SessionToken"])
    require(member.get_account_summary()["SummaryMap"]["Roles"] >= 1,
            "Actual root-task session did not read the member's provisioned access role")
    identity = signed("sts", endpoint, session["AccessKeyId"], session["SecretAccessKey"], session["SessionToken"]).get_caller_identity()
    require(identity["Account"] == out["member_account_id"], "Root-task credentials escaped the owned member")
    rejected(member.create_user, {"AccessDenied"}, UserName="must-not-create-root-task-user")
    iam.disable_organizations_root_credentials_management()
    try:
        rejected(operator.assume_root, {"AccessDenied"}, **arguments)
    finally:
        iam.enable_organizations_root_credentials_management()
    deny = "owned-current-root-audit-deny"
    iam.put_user_policy(UserName=out["operator"], PolicyName=deny, PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "sts:AssumeRoot", "Resource": "*"}]}))
    try:
        rejected(operator.assume_root, {"AccessDenied"}, **arguments)
    finally:
        iam.delete_user_policy(UserName=out["operator"], PolicyName=deny)
    rejected(client("sts", endpoint).assume_root, {"AccessDenied"}, **arguments)
    rejected(signed("secretsmanager", endpoint, out["operator_key"], out["operator_secret"]).list_secrets,
             {"AccessDeniedException"})

    status = account.get_region_opt_status(RegionName=out["region"])["RegionOptStatus"]
    require(status == ("ENABLED" if revision == "v1" else "DISABLED"), "Region update has not reached its retained terminal phase")
    regional = signed("sts", endpoint, "test", "test", region=out["region"])
    if revision == "v1":
        regional_session = regional.get_session_token(DurationSeconds=900)["Credentials"]
        regional_identity = signed("sts", endpoint, regional_session["AccessKeyId"], regional_session["SecretAccessKey"],
                                   regional_session["SessionToken"], region=out["region"]).get_caller_identity()
        require(regional_identity["Account"] == out["account_id"], "Enabled opt-in region issued credentials for a different account")
    else:
        # The disabled regional endpoint rejects authentication before STS runs.
        rejected(regional.get_session_token, {"InvalidClientTokenId"}, DurationSeconds=900)

    role = iam.get_role(RoleName=out["service_linked_role"])["Role"]
    require(role["Description"].endswith(revision), "Service-linked-role description update was not retained")
    attached = iam.list_attached_role_policies(RoleName=out["service_linked_role"])["AttachedPolicies"]
    require({item["PolicyArn"] for item in attached} == {"arn:aws:iam::aws:policy/aws-service-role/AWSElasticLoadBalancingServiceRolePolicy"},
            "Service-linked role does not carry its sourced exact managed policy")
    rejected(client("sts", endpoint).assume_role, {"AccessDenied"}, RoleArn=out["service_linked_role_arn"], RoleSessionName="wrong-human")
    rejected(iam.put_role_policy, {"UnmodifiableEntity"}, RoleName=out["service_linked_role"], PolicyName="must-not-modify",
             PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))
    print(f"Controls complete: {revision}; actual member root-task session, task/current-IAM restrictions, region credential issuance, linked-role protection", flush=True)


def controls_imports(resources):
    names = {"aws_account_region.opt_in", "aws_iam_organizations_features.root_access", "aws_iam_user.root_operator",
             "aws_iam_user_policy.root_operator", "aws_iam_service_linked_role.elb"}
    return {item["address"]: item["values"]["id"] for item in resources if item["address"] in names}


def restore_prerequisites(endpoint, record):
    account, organizations = client("account", endpoint), client("organizations", endpoint)
    current = account.get_region_opt_status(RegionName="ap-southeast-3")["RegionOptStatus"]
    if current in {"ENABLING", "DISABLING"}:
        clock(endpoint, "2m")
        current = account.get_region_opt_status(RegionName="ap-southeast-3")["RegionOptStatus"]
    if current != record["region_status"]:
        method = account.enable_region if record["region_status"] == "ENABLED" else account.disable_region
        method(RegionName="ap-southeast-3")
        clock(endpoint, "2m")
    require(account.get_region_opt_status(RegionName="ap-southeast-3")["RegionOptStatus"] == record["region_status"],
            "Opt-in region before-image not restored")
    # Account deletion is not an AWS API. Close the solely owned local member,
    # remove membership, then delete the organization; do not claim physical erasure.
    if record["member"] is None and record.get("request"):
        deadline = time.monotonic() + 90
        request = organizations.describe_create_account_status(CreateAccountRequestId=record["request"])["CreateAccountStatus"]
        while request["State"] == "IN_PROGRESS":
            require(time.monotonic() < deadline, "Owned account request did not settle for cleanup")
            clock(endpoint, "5s")
            time.sleep(0.1)
            request = organizations.describe_create_account_status(CreateAccountRequestId=record["request"])["CreateAccountStatus"]
        if request["State"] == "SUCCEEDED":
            record["member"] = request["AccountId"]
    if record["member"] is not None:
        organizations.close_account(AccountId=record["member"])
        organizations.remove_account_from_organization(AccountId=record["member"])
    organizations.disable_aws_service_access(ServicePrincipal="iam.amazonaws.com")
    organizations.delete_organization()
    expect_missing(organizations.describe_organization, {"AWSOrganizationsNotInUseException"})


def main():
    parser = arguments(__doc__, 14711)
    parser.add_argument("--consumer-port", type=int, default=14712, help="Unused local password-application port reachable by Docker host gateway")
    parser.add_argument("--dns-port", type=int, default=14713, help="Unused explicit local authoritative DNS UDP/TCP port")
    parser.add_argument("--elbv2-node-executable", type=Path, required=True, help="Installed static Linux native ALB relay matching the Docker host")
    parser.add_argument("--desync-executable", type=Path, required=True, help="Installed adapter linked to the pinned real http-desync-guardian")
    parser.add_argument("--provider-mirror", type=Path, help="Filesystem mirror containing pinned AWS6.68.0; no direct fallback")
    parser.add_argument("--docker-host", default=os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock"))
    parser.add_argument("--architecture", choices=RUNTIMES, default="x86_64")
    parser.add_argument("--desktop", action="store_true")
    args = parser.parse_args()
    require(1024 <= args.consumer_port <= 65535 and args.consumer_port != args.port,
            "Select distinct unprivileged controller/application ports")
    require(1024 <= args.dns_port <= 65535 and args.dns_port not in {args.port, args.consumer_port},
            "Select a separate unprivileged authoritative DNS port")
    require(args.elbv2_node_executable.is_file() and args.desync_executable.is_file(), "Install the genuine relay/desync binaries first")
    require(shutil.which("dig"), "Install the existing BIND dig DNS client; no resolver fallback is allowed")
    require(shutil.which("terraform"), "Install Terraform1.16.6 first")
    previous_umask = os.umask(0o077)
    previous_ca = os.environ.get("SSL_CERT_FILE")
    root = workspace(args, "terraform-identity-extensions")
    root.chmod(0o700)
    endpoint = local_endpoint(f"http://127.0.0.1:{args.port}")
    account_id = str(100_000_000_000 + secrets.randbelow(900_000_000_000))
    evidence = {"terraform": "1.16.6", "provider": "6.68.0", "account_id": account_id,
                "completed_stages": [], "consumer_observations": [], "strict_plans": [], "verified": False}
    latest, prerequisite = None, None
    command_number = 0
    try:
        # Leave a full modeled one-hour immediate-rotation window; do not begin
        # a real four-callback rotation seconds before a clock-hour boundary.
        initial = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0).isoformat().replace("+00:00", "Z")
        save(root / "clock-start.json", {"time": initial})
        variables = {"endpoint": endpoint, "name": "stackd-identity-ext-" + uuid.uuid4().hex[:10], "account_id": account_id,
                     "artifact_directory": str(root), "architecture": args.architecture, "revision": "v1"}
        for module in (credentials, federation, keys, tls):
            variables.update(module.prepare(root))
        variables.update(rotation.prepare(root, args.consumer_port, args.docker_host))
        tls.configure(root, args.docker_host, f"127.0.0.1:{args.dns_port}")
        os.environ["SSL_CERT_FILE"] = str(root / "federation/issuer_ca.pem")
        env = environment()
        version = json.loads(subprocess.check_output(["terraform", "version", "-json"], env=env, text=True))
        require(version["terraform_version"] == "1.16.6", "Fixture pins Terraform exactly1.16.6")
        for image in (STORAGE, TOOLKIT, RUNTIMES[args.architecture]):
            info = json.loads(subprocess.check_output(["docker", "--host", args.docker_host, "image", "inspect", image], env=env, text=True))[0]
            require(info["Os"] == "linux", f"Missing installed Linux prerequisite: {image}")
            if image == RUNTIMES[args.architecture]:
                require(info["Architecture"] == ("amd64" if args.architecture == "x86_64" else "arm64"), "Installed runtime architecture differs")
        helper = args.stackd.resolve().parent / ("lambda-telemetry-amd64" if args.architecture == "x86_64" else "lambda-telemetry-arm64")
        require(helper.is_file(), f"Install existing official-runtime telemetry helper: {helper}")
        for source in HERE.glob("*.tf"):
            shutil.copyfile(source, root / source.name)
        shutil.copyfile(HERE / ".terraform.lock.hcl", root / ".terraform.lock.hcl")
        config = "disable_checkpoint = true\n"
        if args.provider_mirror is not None:
            require(args.provider_mirror.is_dir(), "Provider mirror is missing")
            config += ('provider_installation {\n  filesystem_mirror {\n    path = ' + json.dumps(str(args.provider_mirror.resolve()))
                       + '\n    include = ["registry.terraform.io/hashicorp/aws"]\n  }\n}\n')
        (root / "terraform.rc").write_text(config)
        env["TF_CLI_CONFIG_FILE"] = str(root / "terraform.rc")
        extra = ["-clock-start", initial, "-oidc-discovery", "-docker-host", args.docker_host, "-lambda-runtime",
                 "-compute-endpoint", f"http://host.docker.internal:{args.port}", "-lambda-telemetry-directory", str(args.stackd.resolve().parent)]
        extra += ["-elbv2-node-executable", str(args.elbv2_node_executable.resolve()),
                  "-elbv2-desync-executable", str(args.desync_executable.resolve()),
                  "-dns-listen", f"127.0.0.1:{args.dns_port}"]
        if args.desktop:
            extra += ["-lambda-callback-host", "host.docker.internal"]

        def stage(label):
            evidence["completed_stages"].append(label)
            save(root / "lifecycle.json", evidence)
            print("STAGE COMPLETE:", label, flush=True)

        def configure():
            save(root / "local.auto.tfvars.json", variables)

        def terraform(*command, capture=False, check=True):
            nonlocal command_number
            print("terraform", *command, flush=True)
            command_number += 1
            receipt = root / f"terraform-{command_number:03d}-{command[0]}"
            active = command[0] in {"apply", "import", "destroy"}
            arguments = list(command)
            if command[0] in {"init", "plan", "apply", "import", "destroy"}:
                arguments.insert(1, "-no-color")
            try:
                with ticking(endpoint) if active else contextlib.nullcontext():
                    result = subprocess.run(["terraform", *arguments], cwd=root, env=env,
                                            check=False, text=True, capture_output=True, timeout=900)
                receipt.with_suffix(".stdout").write_text(result.stdout)
                receipt.with_suffix(".stderr").write_text(result.stderr)
                save(receipt.with_suffix(".json"), {"arguments": arguments, "exit_code": result.returncode})
                print(f"Terraform exit {result.returncode}; retained output: {receipt}", flush=True)
                if check:
                    result.check_returncode()
                return result
            finally:
                for pattern in ("*.tfstate*", "*.tfplan", "*.json", "terraform.rc"):
                    for path in root.glob(pattern):
                        if path.is_file():
                            path.chmod(0o600)

        def output():
            return {name: item["value"] for name, item in json.loads(terraform("output", "-json", capture=True).stdout).items()}

        def inspected_readback(label, out):
            """Baseline exactly inspected native consumer-owned computed fields."""
            plan = label + ".consumer-readback.tfplan"
            result = terraform("plan", "-refresh-only", "-input=false", "-detailed-exitcode",
                               "-out=" + plan, check=False)
            require(result.returncode in {0, 2}, f"Consumer readback failed: {result.returncode}")
            observed = json.loads(terraform("show", "-json", plan, capture=True).stdout)
            require(not observed.get("errored") and observed.get("complete") and
                    not observed.get("deferred_changes"), "Consumer observation is incomplete or deferred")
            require(all(row["change"]["actions"] == ["no-op"] for row in observed.get("resource_changes", [])),
                    "Consumer observation contains managed configuration actions")
            require(all(row["actions"] == ["no-op"] for row in observed.get("output_changes", {}).values()),
                    "Consumer observation changes Terraform outputs")
            allowed = {"aws_iam_saml_provider.federation": {"valid_until"},
                       "aws_iam_virtual_mfa_device.credentials": {"enable_date", "user_name"},
                       "aws_secretsmanager_secret_version.seed": {"version_stages"}}
            inspected = []
            for row in observed.get("resource_drift", []):
                change = row["change"]
                before, after = change["before"], change["after"]
                require(before is not None and after is not None and change["actions"] == ["update"],
                        f"Consumer observation unexpectedly creates/deletes {row['address']}")
                fields = {key for key in before.keys() | after.keys() if before.get(key) != after.get(key)}
                require(fields and fields <= allowed.get(row["address"], set()),
                        f"Unrelated native drift remains terminal: {row['address']}: {sorted(fields)}")
                effect = {"address": row["address"], "fields": sorted(fields),
                          "before": {key: before.get(key) for key in sorted(fields)},
                          "after": {key: after.get(key) for key in sorted(fields)}}
                if row["address"] == "aws_iam_virtual_mfa_device.credentials":
                    devices = client("iam", endpoint).list_mfa_devices(UserName=out["credentials"]["user"])["MFADevices"]
                    current = next(item for item in devices if item["SerialNumber"] == out["credentials"]["mfa_serial"])
                    require(after["user_name"] == out["credentials"]["user"] and
                            datetime.fromisoformat(after["enable_date"].replace("Z", "+00:00")) == current["EnableDate"],
                            "MFA readback does not match the declared native enrollment")
                elif row["address"] == "aws_iam_saml_provider.federation":
                    current = client("iam", endpoint).get_saml_provider(SAMLProviderArn=out["federation"]["saml_arn"])
                    require(current["SAMLMetadataDocument"] == (root / f"federation/saml-{variables['revision']}.xml").read_text() and
                            datetime.fromisoformat(after["valid_until"].replace("Z", "+00:00")) == current["ValidUntil"],
                            "SAML readback does not match the restored native metadata")
                else:
                    resource = next(item for item in observed["configuration"]["root_module"]["resources"]
                                    if item["address"] == row["address"])
                    require("version_stages" not in resource.get("expressions", {}),
                            "Configured seed labels cannot be baselined as consumer readback")
                    seed, secret = out["rotation"]["seed_version"], out["rotation"]["secret"]
                    manager = client("secretsmanager", endpoint)
                    native = manager.get_secret_value(SecretId=secret, VersionId=seed)
                    metadata = manager.describe_secret(SecretId=secret)
                    rotation_receipt = json.loads((root / "rotation/evidence.json").read_text())
                    require(before["version_id"] == after["version_id"] == native["VersionId"] == seed and
                            before["secret_id"] == after["secret_id"] == secret and
                            before["version_stages"] == ["AWSPREVIOUS"] and after["version_stages"] == [] and
                            native.get("VersionStages", []) == after["version_stages"] and
                            metadata["VersionIdsToStages"].get(seed, []) == after["version_stages"],
                            "Seed observation is not the exact retired AWSPREVIOUS label")
                    require(rotation_receipt["revision"] == "v2" and
                            set(rotation_receipt["stages"]) == {"createSecret", "setSecret", "testSecret", "finishSecret"} and
                            rotation_receipt["version"] != seed and
                            "AWSCURRENT" in metadata["VersionIdsToStages"].get(rotation_receipt["version"], []),
                            "Seed label retirement lacks the genuine completed second rotation")
                    effect.update({"seed_version": seed, "rotation_version": rotation_receipt["version"],
                                   "finish_secret_receipt": "rotation/evidence.json",
                                   "signed_version_stages": native.get("VersionStages", []),
                                   "signed_version_ids_to_stages": metadata["VersionIdsToStages"]})
                inspected.append(effect)
            config_plan = label + ".consumer-configuration.tfplan"
            configuration = terraform("plan", "-input=false", "-detailed-exitcode", "-out=" + config_plan, check=False)
            require(configuration.returncode == 0, "Consumer readback has real managed configuration drift")
            configured = json.loads(terraform("show", "-json", config_plan, capture=True).stdout)
            require(not configured.get("errored") and configured.get("complete") and
                    not configured.get("deferred_changes") and
                    all(row["change"]["actions"] == ["no-op"] for row in configured.get("resource_changes", [])),
                    "Consumer configuration observation has deferred or managed actions")
            record = {"stage": label, "refresh_exit_code": result.returncode,
                      "configuration_exit_code": configuration.returncode, "inspected_effects": inspected,
                      "saved_plan": plan, "accepted_as_strict_nochange": False}
            evidence["consumer_observations"].append(record)
            save(root / "lifecycle.json", evidence)
            if result.returncode == 2:
                require(inspected, "Nonempty refresh observation has no allowlisted consumer effects")
                terraform("apply", "-input=false", "-auto-approve", plan)

        def stable(label, out):
            inspected_readback(label, out)
            results = []
            for kind, flags in (("refresh-only", ["-refresh-only"]), ("configuration", [])):
                result = terraform("plan", *flags, "-input=false", "-detailed-exitcode",
                                   "-out=" + label + "." + kind + ".tfplan", check=False)
                record = {"stage": label, "kind": kind, "exit_code": result.returncode,
                          "no_change": result.returncode == 0}
                evidence["strict_plans"].append(record)
                results.append(record["no_change"])
                save(root / "lifecycle.json", evidence)
            return all(results)

        def consumers(out, revision):
            verify_controls(endpoint, out["controls"], revision)
            # Key tests advance bounded service time; federation then issues fresh
            # short-lived tokens. MFA always uses the owner's retained clock.
            for name in ("keys", "credentials", "federation", "rotation", "tls"):
                MODULES[name].verify(endpoint, out[name], revision, root)

        initialized = False

        def destroy_and_restore(verify=True):
            nonlocal latest, prerequisite
            if latest is None:
                latest = output() if initialized else {}
            credential_output = latest.get("credentials") or {}
            if initialized and (latest.get("tls") or {}).get("load_balancer"):
                # Destroy the owned auxiliary ALB first. IAM must still reject
                # role deletion while native cleanup or real sessions remain.
                terraform("destroy", "-input=false", "-auto-approve", "-target=aws_lb.identity_tls")
                with ticking(endpoint):
                    tls.wait_retired(endpoint, latest["tls"], root)
                # The existing IAM worker explicitly fences live one-hour service
                # sessions. Let them expire only after their native consumer stops.
                clock(endpoint, "61m")
            if initialized:
                terraform("destroy", "-input=false", "-auto-approve")
            if verify and latest:
                for name, module in MODULES.items():
                    if name in latest:
                        module.verify_deleted(endpoint, latest[name], root)
                if "controls" in latest:
                    controls = latest["controls"]
                    expect_missing(client("iam", endpoint).get_user, {"NoSuchEntity"}, UserName=controls["operator"])
                    expect_missing(client("iam", endpoint).get_role, {"NoSuchEntity"}, RoleName=controls["service_linked_role"])
                    require(not client("iam", endpoint).list_organizations_features().get("EnabledFeatures"), "Root features survived destruction")
            if initialized:
                require(not terraform("state", "list", capture=True).stdout.strip(), "Terraform state is not empty after destroy")
            if (root / "credential-before.json").exists():
                credentials.cleanup(endpoint, credential_output, root)
            if prerequisite is None and (root / "prerequisites.json").exists():
                prerequisite = json.loads((root / "prerequisites.json").read_text())
            if prerequisite is not None:
                restore_prerequisites(endpoint, prerequisite)
            stage("destroy-consumer-absence-global-restore-prerequisite-cleanup" if verify else "failed-run-owned-cleanup")

        with contextlib.ExitStack() as consumers_stack:
            consumers_stack.enter_context(federation.startup(root, endpoint))
            consumers_stack.enter_context(rotation.startup(root))
            with controller(args, root, extra=extra, containers=True, account=account_id):
                try:
                    prerequisite = prerequisites(endpoint, root, variables["name"])
                    variables["member_account_id"] = prerequisite["member"]
                    credentials.capture(endpoint, root)
                    configure()
                    terraform("init", "-input=false", "-lockfile=readonly")
                    initialized = True
                    installed = json.loads(terraform("version", "-json", capture=True).stdout)
                    require(installed["provider_selections"]["registry.terraform.io/hashicorp/aws"] == "6.68.0", "Actual installed provider is not6.68.0")
                    terraform("apply", "-input=false", "-auto-approve")
                    latest = output()
                    variables.update(tls.issue(root, latest["tls"]["dns_name"]))
                    configure()
                    terraform("apply", "-input=false", "-auto-approve")
                    latest = output()
                    stage("owned-native-alb-dns-matching-certificate-https-bootstrap")
                    consumers(latest, "v1")
                    clean = stable("create-nochange", latest)
                    stage("create-v1-real-consumers-" + ("strict-nochange" if clean else "strict-plan-failed"))
                    variables["revision"] = "v2"
                    configure()
                    # AWS6.68 tags before rename and leaves the old ARN known in
                    # downstream plans. Rename only these two real owners first;
                    # then apply tags and the listener against the retained ARN.
                    renamed = terraform("plan", "-input=false", "-detailed-exitcode",
                                        "-target=aws_iam_server_certificate.credentials",
                                        "-target=aws_iam_server_certificate.identity_tls",
                                        "-out=certificate-rename.tfplan", check=False)
                    require(renamed.returncode == 2, "Expected the two declared certificate rename/path updates")
                    rename_plan = json.loads(terraform("show", "-json", "certificate-rename.tfplan", capture=True).stdout)
                    changes = [row for row in rename_plan.get("resource_changes", [])
                               if row["change"]["actions"] != ["no-op"]]
                    require(not rename_plan.get("errored") and not rename_plan.get("deferred_changes") and
                            {row["address"] for row in changes} ==
                            {"aws_iam_server_certificate.credentials", "aws_iam_server_certificate.identity_tls[0]"},
                            "Certificate stage contains unrelated or deferred resource changes")
                    for row in changes:
                        change = row["change"]
                        fields = {key for key in change["before"].keys() | change["after"].keys()
                                  if change["before"].get(key) != change["after"].get(key)}
                        require(change["actions"] == ["update"] and {"name", "path"} <= fields <= {"name", "path", "arn"},
                                f"Certificate stage is not a pure native rename/path update: {row['address']}: {fields}")
                    terraform("apply", "-input=false", "-auto-approve", "certificate-rename.tfplan")
                    variables["certificate_tag_revision"] = "v2"
                    configure()
                    terraform("apply", "-input=false", "-auto-approve")
                    latest = output()
                    consumers(latest, "v2")
                    clean = stable("update-nochange", latest)
                    stage("update-v2-real-consumers-" + ("strict-nochange" if clean else "strict-plan-failed"))
                    resources = json.loads(terraform("show", "-json", capture=True).stdout)["values"]["root_module"]["resources"]
                    imported = controls_imports(resources)
                    for module in MODULES.values():
                        imported.update(module.imports(resources))
                    save(root / "imports.json", imported)
                    for address, identifier in imported.items():
                        terraform("state", "rm", address)
                        terraform("import", "-input=false", address, identifier)
                    reconciliation = terraform("plan", "-input=false", "-detailed-exitcode",
                                               "-out=import-reconcile.tfplan", check=False)
                    require(reconciliation.returncode in {0, 2}, "Native import reconciliation failed")
                    reconcile_plan = json.loads(terraform("show", "-json", "import-reconcile.tfplan", capture=True).stdout)
                    require(not reconcile_plan.get("errored") and reconcile_plan.get("complete") and
                            not reconcile_plan.get("deferred_changes") and
                            all(row["change"]["actions"] in (["no-op"], ["update"])
                                for row in reconcile_plan.get("resource_changes", [])),
                            "Native import must preserve every real identity; create/delete/replacement is forbidden")
                    terraform("apply", "-input=false", "-auto-approve", "import-reconcile.tfplan")
                    latest = output()
                    consumers(latest, "v2")
                    clean = stable("import-nochange", latest)
                    stage("native-import-reconcile-" + ("strict-nochange" if clean else "strict-plan-failed"))
                except BaseException:
                    destroy_and_restore(verify=False)
                    raise
            shutil.copyfile(root / "stackd.log", root / "before-reopen.stackd.log")
            stage("owned-controller-stopped")
            # Same SQLite file, exact endpoint and saved service clock. No reseed,
            # fake reconstruction, provider state-only refresh or fresh account.
            with controller(args, root, extra=extra, containers=True, account=account_id):
                try:
                    latest = output()
                    consumers(latest, "v2")
                    clean = stable("reopen-nochange", latest)
                    stage("sqlite-reopen-existing-ciphertext-sessions-password-" + ("strict-nochange" if clean else "strict-plan-failed"))
                finally:
                    destroy_and_restore()
            shutil.copyfile(root / "stackd.log", root / "after-reopen.stackd.log")
        stage("all-owned-processes-closed")
        failures = [record for record in evidence["strict_plans"] if not record["no_change"]]
        require(not failures, f"Consumers and cleanup completed, but strict plans failed: {failures}; inspect {root}")
        evidence["verified"] = True
        save(root / "lifecycle.json", evidence)
        print(f"Identity extensions lifecycle complete. Sensitive artifacts stay private: {root}", flush=True)
    finally:
        if previous_ca is None:
            os.environ.pop("SSL_CERT_FILE", None)
        else:
            os.environ["SSL_CERT_FILE"] = previous_ca
        os.umask(previous_umask)


if __name__ == "__main__":
    main()
