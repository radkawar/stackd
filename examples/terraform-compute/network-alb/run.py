"""Current AWS 6.68.0 network/ALB lifecycle with owned real ECS target consumers."""

import contextlib
import ipaddress
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import uuid
from urllib.request import ProxyHandler, build_opener

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from local import arguments, client, controller, environment, expect_missing, require, workspace
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))
from dns_http_client import opener, query


def main():
    parser = arguments(__doc__, 14707)
    parser.add_argument("--provider-mirror", type=Path)
    parser.add_argument("--variables", type=Path, help="JSON fixture variables for genuine prepared target endpoints/topology")
    parser.add_argument("--network-only", action="store_true", help="Exercise network resources without claiming ALB packet execution")
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    parser.add_argument("--elbv2-node-executable", type=Path)
    parser.add_argument("--desync-executable", type=Path, help="Installed adapter linked to the pinned official http-desync-guardian")
    parser.add_argument("--image", default="busybox:1.36.1", help="Installed Linux/amd64 BusyBox with httpd; never pulled")
    args = parser.parse_args()
    require(shutil.which("terraform"), "Install official Terraform 1.15.9 or later first")
    env = environment()
    version = json.loads(subprocess.run(["terraform", "version", "-json"], env=env, check=True, text=True, capture_output=True).stdout)
    require(tuple(map(int, version["terraform_version"].split("."))) >= (1, 15, 9),
            "This fixture requires official Terraform 1.15.9 or later")
    variables = json.loads(args.variables.read_text()) if args.variables else {}
    require(isinstance(variables, dict) and not {"endpoint", "name", "revision", "enable_alb", "enable_target", "target_image"}.intersection(variables), "Fixture variables cannot override lifecycle ownership")
    if not args.network_only:
        require(args.elbv2_node_executable and args.elbv2_node_executable.is_file(), "Supply the installed genuine ALB relay executable")
        require(not variables.get("targets") or variables.get("expected_target_body"), "Forwarding requires an exact expected target response body")
        require(args.desync_executable and args.desync_executable.is_file(), "Supply the installed genuine desync classifier adapter")
    owned_target = not args.network_only and not variables.get("targets")

    def docker(*command):
        return subprocess.run(["docker", "--host", args.docker_host, *command], env=env,
                              check=True, text=True, capture_output=True).stdout

    if owned_target:
        image = json.loads(docker("image", "inspect", args.image))[0]
        require(image["Os"] == "linux" and image["Architecture"] == "amd64",
                "Target image must be an installed Linux/amd64 image")
    root = workspace(args, "terraform-network-alb")
    root.chmod(0o700)  # State and outputs stay private; no guest bind mounts here.
    shutil.copyfile(Path(__file__).with_name("main.tf"), root / "main.tf")
    shutil.copyfile(Path(__file__).resolve().parents[1] / ".terraform.lock.hcl",
                    root / ".terraform.lock.hcl")
    installation = "disable_checkpoint = true\n"
    if args.provider_mirror:
        require(args.provider_mirror.is_dir(), "Prepared provider mirror does not exist")
        installation += "provider_installation {\n  filesystem_mirror {\n    path = " + json.dumps(str(args.provider_mirror.resolve())) + '\n    include = ["registry.terraform.io/hashicorp/aws"]\n  }\n}\n'
    (root / "terraform.rc").write_text(installation)
    env["TF_CLI_CONFIG_FILE"] = str(root / "terraform.rc")

    def terraform(*command, capture=False, check=True):
        print("terraform", *command, flush=True)
        return subprocess.run(["terraform", *command], cwd=root, env=env, check=check, text=True, capture_output=capture)

    extra = []
    dns_endpoint = None
    if not args.network_only:
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            dns_endpoint = "127.0.0.1:" + str(reservation.getsockname()[1])
        extra = ["-docker-host", args.docker_host, "-elbv2-node-executable", str(args.elbv2_node_executable.resolve()),
                 "-elbv2-desync-executable", str(args.desync_executable.resolve()), "-dns-listen", dns_endpoint]
        if owned_target:
            extra += ["-ecs-runtime"]
    with contextlib.ExitStack() as runtime:
        endpoint = runtime.enter_context(
            controller(args, root, extra=extra, containers=not args.network_only))
        variables.update(endpoint=endpoint, name="tf-net-" + uuid.uuid4().hex[:10], revision="one",
                         enable_alb=not args.network_only and not owned_target,
                         enable_target=owned_target, target_image=args.image)
        variable_file = root / "local.auto.tfvars.json"

        def save_variables():
            variable_file.write_text(json.dumps(variables))
            variable_file.chmod(0o600)

        save_variables()
        terraform("init", "-input=false")
        ec2 = client("ec2", endpoint)
        elb = client("elbv2", endpoint)
        ecs = client("ecs", endpoint)
        seen_containers = set()
        outputs = None

        def output():
            value = json.loads(terraform("output", "-json", "consumer", capture=True).stdout)
            (root / "outputs.json").write_text(json.dumps(value, indent=2) + "\n")
            return value
        def consume_target(value):
            listed = ecs.list_tasks(cluster=value["target_cluster"], serviceName=value["target_service"], desiredStatus="RUNNING")["taskArns"]
            tasks = ecs.describe_tasks(cluster=value["target_cluster"], tasks=listed)["tasks"] if listed else []
            require(len(tasks) == 1 and tasks[0]["lastStatus"] == "RUNNING", "Owned target is not one real running task")
            task = tasks[0]
            ids = docker("ps", "-aq", "--filter", "label=stackd.ecs.task=" + task["taskArn"],
                         "--filter", "label=stackd.ecs.role=container").split()
            require(len(ids) == 1, "Owned target has no exact native customer container")
            native = json.loads(docker("inspect", ids[0]))[0]
            require(native["Config"]["Labels"].get("stackd.ecs.task") == task["taskArn"]
                    and native["State"]["Running"] and native["State"]["Pid"] > 0,
                    "Target metadata does not identify a real process")
            require("ALB_TARGET:" + variables["revision"] in docker("logs", ids[0]), "Native target output has wrong revision")
            interfaces = task["containers"][0].get("networkInterfaces", [])
            require(len(interfaces) == 1, "Native target has no single network attachment")
            address = ipaddress.ip_address(interfaces[0]["privateIpv4Address"])
            subnet = ec2.describe_subnets(SubnetIds=[value["subnet_ids"][0]])["Subnets"][0]
            require(address in ipaddress.ip_network(subnet["CidrBlock"]), "Native target escaped the owned subnet")
            body = "target-" + variables["revision"] + "\n"
            port = variables.get("listener_port", 8080)
            with build_opener(ProxyHandler({})).open(f"http://{address}:{port}/forward", timeout=10) as response:
                require(response.read().decode() == body, "Independent native target bytes differ from deployed revision")
            seen_containers.add(ids[0])
            print(f"Consumed native target PID {native['State']['Pid']}, output and private-IP HTTP bytes", flush=True)
            return {"owned": {"ip": str(address), "port": port, "availability_zone": subnet["AvailabilityZone"]}}, body

        def attach_target(value):
            variables["targets"], variables["expected_target_body"] = consume_target(value)
            variables["enable_alb"] = True
            save_variables()
            terraform("apply", "-input=false", "-auto-approve")
            return output()

        def verify(value):
            print("Stage: signed network reads and real ALB consumers", flush=True)
            vpc = ec2.describe_vpcs(VpcIds=[value["vpc_id"]])["Vpcs"]
            require(len(vpc) == 1 and vpc[0]["CidrBlock"] == variables.get("vpc_cidr", "10.179.0.0/16"), "VPC output does not match actual EC2 state")
            subnets = ec2.describe_subnets(SubnetIds=value["subnet_ids"])["Subnets"]
            require(len(subnets) == 2 and len({s["AvailabilityZone"] for s in subnets}) == 2, "Subnet output lost AZ distribution")
            eni = ec2.describe_network_interfaces(NetworkInterfaceIds=[value["interface_id"]])["NetworkInterfaces"][0]
            require(eni["SubnetId"] == value["subnet_ids"][0] and [g["GroupId"] for g in eni["Groups"]] == [value["group_id"]], "ENI output lost actual subnet/security-group ownership")
            require(eni["Description"] == "Terraform revision " + value["revision"], "ENI update did not reach EC2")
            if args.network_only:
                return
            deadline = time.monotonic() + 180
            http = opener(dns_endpoint)
            while True:
                try:
                    answer = query(dns_endpoint, value["dns_name"])
                    require(answer["status"] == "NOERROR" and answer["records"], "ALB has no real DNS address")
                    url = f'http://{value["dns_name"]}:{value["listener_port"]}'
                    with http.open(url + "/fixed", timeout=5) as response:
                        require(response.status == 200 and response.read().decode() == "fixed-" + value["revision"], "Fixed response does not match listener revision")
                    if value["targets"]:
                        health = elb.describe_target_health(TargetGroupArn=value["target_group_arn"])["TargetHealthDescriptions"]
                        require(len(health) == len(value["targets"]) and all(t["TargetHealth"]["State"] == "healthy" for t in health), "Actual HTTP probes have not established target health")
                        with http.open(url + "/forward", timeout=5) as response:
                            require(response.status == 200 and response.read().decode() == value["expected_target_body"], "ALB did not forward genuine target response bytes")
                    break
                except Exception:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(1)
            print("Verified real DNS, fixed response" + (" and healthy-target forwarding" if value["targets"] else " (no forwarding targets supplied)"), flush=True)

        plan_failures = []
        plan_number = 0

        def no_change():
            nonlocal plan_number
            plan_number += 1
            print("Stage: refresh-only and ordinary no-change plans", flush=True)
            for mode in ("-refresh-only", None):
                filename = f"noop-{plan_number}-{'refresh' if mode else 'ordinary'}.tfplan"
                command = ["plan", "-input=false", "-detailed-exitcode", "-out=" + filename]
                if mode:
                    command.append(mode)
                result = terraform(*command, check=False)
                if result.returncode != 0:
                    failure = f"Plan {plan_number} {mode or 'ordinary'} was not a no-op: {result.returncode}"
                    plan_failures.append(failure)
                    print("FAILED assertion: " + failure, flush=True)
                elif mode:
                    terraform("apply", "-input=false", "-auto-approve", filename)

        try:
            print("Stage: create (unsupported native settings must fail explicitly)", flush=True)
            terraform("apply", "-input=false", "-auto-approve")
            if owned_target:
                print("Stage: native ECS target bootstrap and independent bytes before ALB", flush=True)
                outputs = attach_target(output())
            outputs = output()
            verify(outputs)
            no_change()
            print("Stage: import existing native identities", flush=True)
            imports = {"aws_vpc.network": outputs["vpc_id"], "aws_security_group.network": outputs["group_id"], "aws_network_interface.network": outputs["interface_id"]}
            imports.update({f"aws_subnet.zone[{i}]": subnet for i, subnet in enumerate(outputs["subnet_ids"])})
            if not args.network_only:
                imports.update({"aws_lb.network[0]": outputs["load_balancer_arn"], "aws_lb_listener.network[0]": outputs["listener_arn"]})
                if outputs["target_group_arn"]:
                    imports.update({"aws_lb_target_group.network[0]": outputs["target_group_arn"], "aws_lb_listener_rule.forward[0]": outputs["rule_arn"]})
                    for key, target in outputs["targets"].items():
                        address = "aws_lb_target_group_attachment.network[" + json.dumps(key) + "]"
                        imports[address] = ",".join([outputs["target_group_arn"], target["ip"], str(target["port"]), target["availability_zone"]])
                if owned_target:
                    imports.update({
                        "aws_ecs_cluster.target[0]": variables["name"] + "-target",
                        "aws_ecs_task_definition.target[0]": outputs["target_definition"],
                        "aws_ecs_service.target[0]": variables["name"] + "-target/" + variables["name"] + "-target",
                        "aws_iam_role.target_task[0]": variables["name"] + "-target-task",
                        "aws_iam_role.target_execution[0]": variables["name"] + "-target-execution",
                        "aws_iam_role_policy.target_execution[0]": variables["name"] + "-target-execution:execution"
                    })
            # Native attachments are imported using the provider's structured
            # target-group ARN,target ID,port,AZ form documented in procedure.json.
            backup = root / "before-import.tfstate"
            backup.write_text(terraform("state", "pull", capture=True).stdout)
            backup.chmod(0o600)
            try:
                for address, identity in imports.items():
                    terraform("state", "rm", address)
                    terraform("import", "-input=false", address, identity)
            except BaseException:
                # This private fixture has no shared/remote backend. Restore its
                # exact owned pre-import IDs so finally-destroy cannot orphan a
                # resource whose importer failed. Keep the original failure.
                terraform("state", "push", "-force", str(backup))
                raise
            no_change()
            verify(output())
            print("Stage: update retained resources", flush=True)
            variables["revision"] = "two"
            save_variables()
            terraform("apply", "-input=false", "-auto-approve")
            updated = output()
            if owned_target:
                updated = attach_target(updated)
            require(updated["vpc_id"] == outputs["vpc_id"] and updated["interface_id"] == outputs["interface_id"], "Update unexpectedly replaced network ownership")
            verify(updated)
            no_change()
            print("Stage: reopen the same owned database and consume retained resources", flush=True)
            runtime.close()
            endpoint = runtime.enter_context(
                controller(args, root, extra=extra, containers=not args.network_only))
            if owned_target:
                targets, body = consume_target(updated)
                require(targets == updated["targets"] and body == updated["expected_target_body"],
                        "Reopen changed the native target address or bytes")
            verify(updated)
            no_change()
        finally:
            print("Stage: destroy (retaining artifacts on explicit failure)", flush=True)
            terraform("destroy", "-input=false", "-auto-approve")
            if outputs:
                expect_missing(ec2.describe_vpcs, {"InvalidVpcID.NotFound"}, VpcIds=[outputs["vpc_id"]])
                expect_missing(ec2.describe_network_interfaces, {"InvalidNetworkInterfaceID.NotFound"}, NetworkInterfaceIds=[outputs["interface_id"]])
                if outputs["load_balancer_arn"]:
                    expect_missing(elb.describe_load_balancers, {"LoadBalancerNotFound"}, LoadBalancerArns=[outputs["load_balancer_arn"]])
                if owned_target:
                    for suffix in ("target-task", "target-execution"):
                        expect_missing(client("iam", endpoint).get_role, {"NoSuchEntity"}, RoleName=variables["name"] + "-" + suffix)
                    remaining = docker("ps", "-aq").split()
                    require(not seen_containers.intersection(remaining), "Owned target container remains after destroy")
                    require(not ec2.describe_network_interfaces(Filters=[{"Name": "vpc-id", "Values": [outputs["vpc_id"]]}])["NetworkInterfaces"],
                            "Owned target/LB managed ENI remains after destroy")
            state = json.loads(terraform("show", "-json", capture=True).stdout)
            resources = state.get("values", {}).get("root_module", {}).get("resources", [])
            require(not any(row.get("mode") == "managed" for row in resources), "Destroy left managed Terraform resources")
        require(not plan_failures, "; ".join(plan_failures))
    print(f"Lifecycle completed; owned artifacts retained at {root}")


if __name__ == "__main__":
    main()
