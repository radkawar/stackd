"""Current-provider Auto Scaling with actual QEMU guests, policy execution and refresh."""

import ipaddress
import json
from pathlib import Path
import random
import sys
import time
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compute import ACCOUNT, Terraform, client, parser, require


def main():
    options = parser(__doc__)
    options.add_argument("--image-id", required=True, help="Actually imported Linux HVM cloud-init image with Python 3")
    options.add_argument("--account-id", default=ACCOUNT, help="Explicit account of the caller-owned native controller")
    options.add_argument("--subnet-cidr", type=ipaddress.IPv4Network,
                         help="Unique owned native guest subnet")
    args = options.parse_args()
    require(args.endpoint, "This guest fixture requires a caller-owned EC2/QEMU runtime via --endpoint; follow docs/runtime-vms.md")
    fixture = Terraform(args, Path(__file__).resolve().parent)
    name = "tf-asg-" + uuid.uuid4().hex[:12]
    subnet = args.subnet_cidr or ipaddress.ip_network(
        f"10.{random.SystemRandom().randrange(130, 220)}.0.0/24")
    vpc = ipaddress.ip_network(f"{subnet.network_address}/16", strict=False)
    seen = set()
    outputs = None
    with fixture.endpoint() as endpoint:
        ec2 = client("ec2", endpoint)
        scaling = client("autoscaling", endpoint)
        image = ec2.describe_images(ImageIds=[args.image_id])["Images"]
        require(len(image) == 1 and image[0]["State"] == "available", "Guest image is not actually imported and available")
        fixture.configure(endpoint=endpoint, name=name, image_id=args.image_id,
                          revision="create", desired_capacity=1,
                          vpc_cidr=str(vpc), subnet_cidr=str(subnet))
        fixture.command("init", "-input=false")

        def guests(expected, revision):
            deadline = time.monotonic() + 600
            opener = build_opener(ProxyHandler({}))
            last = None
            while time.monotonic() < deadline:
                groups = scaling.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]
                require(len(groups) == 1, "Owned Auto Scaling group disappeared")
                group = groups[0]
                members = group.get("Instances", [])
                for row in members:
                    seen.add(row["InstanceId"])
                if group["DesiredCapacity"] != expected or len(members) != expected or not all(row["LifecycleState"] == "InService" for row in members):
                    time.sleep(1)
                    continue
                ids = [row["InstanceId"] for row in members]
                reservations = ec2.describe_instances(InstanceIds=ids)["Reservations"]
                instances = [row for reservation in reservations for row in reservation["Instances"]]
                if len(instances) != expected or not all(row["State"]["Name"] == "running" for row in instances):
                    time.sleep(1)
                    continue
                complete = True
                for instance in instances:
                    address = ipaddress.ip_address(instance["PrivateIpAddress"])
                    require(address in subnet, "Guest escaped the owned subnet")
                    try:
                        with opener.open(f"http://{address}:8080/", timeout=3) as response:
                            body = response.read()
                        console = ec2.get_console_output(
                            InstanceId=instance["InstanceId"], Latest=True).get("Output", "")
                        if body != (revision + "\n").encode() or "ASG:" + revision not in console:
                            complete = False
                            last = f"{instance['InstanceId']}: console/HTTP revision is not {revision}"
                    except (URLError, TimeoutError, OSError) as error:
                        complete = False
                        last = str(error)
                if complete:
                    print(f"Consumed {expected} actual ASG guests: console marker and independent native HTTP bytes for {revision}", flush=True)
                    return ids
                time.sleep(1)
            raise RuntimeError(f"Actual guest consumer did not settle: {last}")

        try:
            fixture.command("apply", "-input=false", "-auto-approve")
            outputs = fixture.output()
            require(outputs["read_name"] == name and name in outputs["listed_names"], "Terraform Auto Scaling data sources differ from owner state")
            original = guests(1, "create")
            fixture.no_change("create")
            # AWS 6.68.0 omits configured zero on Create, then sends it on Update.
            plan = json.loads(fixture.command(
                "show", "-json", "create-ordinary.tfplan", capture=True).stdout)
            changes = [row for row in plan.get("resource_changes", [])
                       if row["mode"] == "managed" and row["change"]["actions"] != ["no-op"]]
            require(len(changes) == 1 and changes[0]["address"] == "aws_autoscaling_group.compute",
                    "Initial provider convergence contains unrelated managed changes")
            change = changes[0]["change"]
            before, after = change["before"], change["after"]
            different = {key for key in before.keys() | after.keys()
                         if before.get(key) != after.get(key)}
            require(different == {"default_cooldown"} and before["default_cooldown"] == 300
                    and after["default_cooldown"] == 0,
                    "Initial provider convergence is not the declared zero cooldown")
            fixture.command("apply", "-input=false", "-auto-approve")
            require(scaling.describe_auto_scaling_groups(
                AutoScalingGroupNames=[name])["AutoScalingGroups"][0]["DefaultCooldown"] == 0,
                "Declared zero cooldown did not converge")
            fixture.no_change("converged")
            fixture.reimport("aws_autoscaling_group.compute", name)
            fixture.command("apply", "-input=false", "-auto-approve")
            fixture.no_change("import")
            scaling.execute_policy(AutoScalingGroupName=name, PolicyName=outputs["policy"], HonorCooldown=False)
            increased = guests(2, "create")
            require(set(increased) - set(original), "Scaling policy changed counters without launching another guest")
            scaling.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=1, HonorCooldown=False)
            guests(1, "create")
            print("Completed real SimpleScaling execution and restored Terraform desired capacity", flush=True)
            fixture.configure(revision="update", desired_capacity=2)
            fixture.command("apply", "-input=false", "-auto-approve")
            outputs = fixture.output()
            refreshed = guests(2, "update")
            require(not set(refreshed).intersection(original), "Launch-template update did not refresh the original guest")
            fixture.no_change("update")
        finally:
            for group in scaling.describe_auto_scaling_groups(
                    AutoScalingGroupNames=[name])["AutoScalingGroups"]:
                seen.update(row["InstanceId"] for row in group.get("Instances", []))
            fixture.destroy()
            require(not scaling.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"], "Auto Scaling group remains")
            for identity in seen:
                reservations = ec2.describe_instances(InstanceIds=[identity])["Reservations"]
                require(all(row["State"]["Name"] == "terminated" for reservation in reservations for row in reservation["Instances"]), "Owned guest is not terminated")
            if outputs:
                require(not ec2.describe_network_interfaces(Filters=[{"Name": "vpc-id", "Values": [outputs["vpc"]]}])["NetworkInterfaces"], "Guest ENI remains after destroy")
            print("Completed signed API deletion, guest termination and managed ENI cleanup checks", flush=True)
    print(f"Completed Auto Scaling guest fixture. Caller runtime stays running; private artifacts: {fixture.directory}", flush=True)


if __name__ == "__main__":
    main()
