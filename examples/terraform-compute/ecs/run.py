"""Current-provider ECS service/task execution and Application Auto Scaling lifecycle."""

import ipaddress
import json
from pathlib import Path
import random
import subprocess
import sys
import time
from urllib.request import ProxyHandler, build_opener
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compute import ACCOUNT, Terraform, client, environment, parser, require


def main():
    options = parser(__doc__)
    options.add_argument("--image", default="busybox:1.36.1", help="Already installed Linux/amd64 BusyBox with httpd")
    args = options.parse_args()
    require(not args.endpoint, "The complete lifecycle requires a fixture-owned controller for reopen")
    fixture = Terraform(args, Path(__file__).resolve().parent)
    name = "tf-ecs-" + uuid.uuid4().hex[:12]
    octet = random.SystemRandom().randrange(130, 220)
    subnet = ipaddress.ip_network(f"10.{octet}.0.0/24")
    extra = ("-docker-host", args.docker_host, "-ecs-runtime")
    docker_env = environment()
    docker_env["DOCKER_HOST"] = args.docker_host

    def docker(*command):
        return subprocess.run(["docker", *command], env=docker_env, check=True,
                              text=True, capture_output=True).stdout

    # Inspect only. This fixture never pulls or modifies the source image.
    image = json.loads(docker("image", "inspect", args.image))[0]
    require(image["Os"] == "linux" and image["Architecture"] == "amd64",
            "The fixture image must be an installed Linux/amd64 image")
    with fixture.endpoint(extra=extra, containers=True) as endpoint:
        ecs = client("ecs", endpoint)
        scaling = client("application-autoscaling", endpoint)
        iam = client("iam", endpoint)
        fixture.configure(endpoint=endpoint, name=name, image=args.image,
                          revision="create", desired_count=1,
                          vpc_cidr=f"10.{octet}.0.0/16", subnet_cidr=str(subnet))
        fixture.command("init", "-input=false")
        outputs = None
        standalone = []
        seen = set()

        def tasks_for_service(expected):
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                service = ecs.describe_services(cluster=outputs["cluster"], services=[outputs["service"]])["services"][0]
                listed = ecs.list_tasks(cluster=outputs["cluster"], serviceName=outputs["service"], desiredStatus="RUNNING")["taskArns"]
                tasks = ecs.describe_tasks(cluster=outputs["cluster"], tasks=listed)["tasks"] if listed else []
                if service["desiredCount"] == expected and service["runningCount"] == expected and len(tasks) == expected and all(row["lastStatus"] == "RUNNING" for row in tasks):
                    return tasks
                require(service["status"] == "ACTIVE", f"Service left ACTIVE state: {service}")
                time.sleep(0.5)
            raise RuntimeError("Real service task capacity did not settle")

        def consume(task, revision):
            arn = task["taskArn"]
            ids = docker("ps", "-aq", "--filter", "label=stackd.ecs.task=" + arn,
                         "--filter", "label=stackd.ecs.role=container").split()
            require(len(ids) == 1, f"Expected one exact-owned native application container: {ids}")
            native = json.loads(docker("inspect", ids[0]))[0]
            require(native["Config"]["Labels"].get("stackd.ecs.task") == arn
                    and native["State"]["Running"] and native["State"]["Pid"] > 0,
                    "Task metadata does not identify a real running process")
            require("COMPUTE:" + revision in docker("logs", ids[0]), "Native container output has wrong revision")
            interfaces = task["containers"][0].get("networkInterfaces", [])
            require(len(interfaces) == 1, "Task has no single real network attachment")
            address = ipaddress.ip_address(interfaces[0]["privateIpv4Address"])
            require(address in subnet, "Task address escaped the owned subnet")
            opener = build_opener(ProxyHandler({}))
            with opener.open(f"http://{address}:8080/", timeout=10) as response:
                require(response.read() == (revision + "\n").encode(), "Real task HTTP bytes differ from its deployed revision")
            seen.add(ids[0])
            print(f"Consumed native task {arn}: PID {native['State']['Pid']}, Docker output and HTTP revision {revision}", flush=True)
            return ids[0]

        def standalone_task(revision):
            result = ecs.run_task(cluster=outputs["cluster"], taskDefinition=outputs["definition"],
                                  networkConfiguration={"awsvpcConfiguration": {
                                      "subnets": [outputs["subnet"]], "securityGroups": [outputs["security_group"]]}})
            require(not result.get("failures") and len(result["tasks"]) == 1, "RunTask failed")
            arn = result["tasks"][0]["taskArn"]
            standalone.append(arn)
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                task = ecs.describe_tasks(cluster=outputs["cluster"], tasks=[arn])["tasks"][0]
                if task["lastStatus"] == "RUNNING" and task.get("healthStatus") == "HEALTHY":
                    consume(task, revision)
                    require(task.get("capacityProviderName") == "FARGATE",
                            "Standalone task did not use the retained cluster capacity default")
                    ecs.stop_task(cluster=outputs["cluster"], task=arn, reason="Standalone consumer complete")
                    ecs.get_waiter("tasks_stopped").wait(cluster=outputs["cluster"], tasks=[arn],
                                                       WaiterConfig={"Delay": 1, "MaxAttempts": 120})
                    standalone.remove(arn)
                    return
                require(task["lastStatus"] != "STOPPED", f"Standalone task stopped before real execution: {task}")
                time.sleep(0.5)
            raise RuntimeError("Standalone native task did not become healthy")

        try:
            fixture.command("apply", "-input=false", "-auto-approve")
            outputs = fixture.output()
            require(outputs["cluster"] == outputs["read_cluster"]
                    and outputs["definition"] == outputs["read_definition"]
                    and outputs["read_image"] == args.image
                    and outputs["cluster"] in outputs["listed_clusters"],
                    "Terraform data sources do not match managed compute resources")
            for task in tasks_for_service(1):
                consume(task, "create")
            standalone_task("create")
            fixture.no_change("create")
            fixture.reimport("aws_ecs_cluster.compute", outputs["cluster_name"])
            fixture.command("apply", "-input=false", "-auto-approve")
            fixture.no_change("import")

            # This is an independent capacity consumer. The actual scaling
            # owner must start a second native task, not just change a counter.
            scaling.register_scalable_target(ServiceNamespace="ecs", ResourceId=outputs["scaling_target"],
                                             ScalableDimension="ecs:service:DesiredCount", MinCapacity=2, MaxCapacity=2)
            for task in tasks_for_service(2):
                consume(task, "create")
            scaling.register_scalable_target(ServiceNamespace="ecs", ResourceId=outputs["scaling_target"],
                                             ScalableDimension="ecs:service:DesiredCount", MinCapacity=1, MaxCapacity=3)
            ecs.update_service(cluster=outputs["cluster"], service=outputs["service"], desiredCount=1)
            tasks_for_service(1)
            print("Completed real Application Auto Scaling capacity reconciliation and restored Terraform intent", flush=True)

            fixture.configure(revision="update", desired_count=2)
            fixture.command("apply", "-input=false", "-auto-approve")
            outputs = fixture.output()
            for task in tasks_for_service(2):
                consume(task, "update")
            standalone_task("update")
            fixture.no_change("update")
            fixture.reopen()
            for task in tasks_for_service(2):
                consume(task, "update")
            fixture.no_change("reopen")
        finally:
            for arn in standalone:
                ecs.stop_task(cluster=outputs["cluster"], task=arn, reason="Owned Terraform fixture cleanup")
            if standalone:
                ecs.get_waiter("tasks_stopped").wait(cluster=outputs["cluster"], tasks=standalone,
                                                   WaiterConfig={"Delay": 1, "MaxAttempts": 120})
            fixture.destroy()
            cluster = ecs.describe_clusters(clusters=[name])["clusters"]
            require(not cluster or len(cluster) == 1 and cluster[0]["status"] == "INACTIVE"
                    and cluster[0]["runningTasksCount"] == 0,
                    "Deleted cluster did not retain native INACTIVE/zero-running state")
            require(not scaling.describe_scalable_targets(ServiceNamespace="ecs", ResourceIds=[f"service/{name}/{name}"])["ScalableTargets"], "Scaling target remains")
            if outputs:
                require(not client("ec2", endpoint).describe_network_interfaces(Filters=[{"Name": "vpc-id", "Values": [outputs["vpc"]]}])["NetworkInterfaces"], "Native managed ENI remains")
            remaining = docker("ps", "-aq").split()
            require(not seen.intersection(remaining), "Owned customer container remains after destroy")
            labeled = docker("ps", "-aq", "--filter", "label=stackd.ecs.task").split()
            if labeled:
                native = json.loads(docker("inspect", *labeled))
                prefix = f"arn:aws:ecs:us-east-1:{ACCOUNT}:task/{name}/"
                require(not any(row["Config"]["Labels"].get("stackd.ecs.task", "").startswith(prefix)
                                for row in native), "An exact-owned native task container remains")
            from local import expect_missing
            for suffix in ("task", "execution"):
                expect_missing(iam.get_role, {"NoSuchEntity"}, RoleName=name + "-" + suffix)
            print("Completed independent signed-API and native-container cleanup checks", flush=True)
    print(f"Completed ECS/AppAutoScaling fixture. Private artifacts: {fixture.directory}", flush=True)


if __name__ == "__main__":
    main()
