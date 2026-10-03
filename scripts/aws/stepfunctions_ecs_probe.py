#!/usr/bin/env python3
"""Capture bounded optimized ECS workflows using existing public AWS networking.

Requires an explicitly selected existing public subnet. Creates no VPC, routes,
NAT, EC2 instances, or persistent compute. Reuses aws_cli and the existing native
workflow capture/ownership-cleanup conventions. --cleanup resumes after a crash.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import time
import traceback
import uuid

from aws_cli import observe, require_account

RULE = "StepFunctionsGetEventsForECSTaskRule"
IMAGE = "public.ecr.aws/lambda/python:3.12"


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--subnet", required=True)
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/stepfunctions/ecs_workflows.json"))
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument("--admission-only", action="store_true", help="Read-only schema cases; subnet is only an unused syntactic fixture value")
    parser.add_argument("--api-errors-only", action="store_true", help="TestState against absent resources using one temporary role; no compute or networking")
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    env = dict(os.environ, AWS_REGION=args.region, AWS_DEFAULT_REGION=args.region, AWS_MAX_ATTEMPTS="2")
    require_account(args.account, env=env)
    if args.output.exists() and not args.cleanup:
        raise RuntimeError("Refusing to overwrite existing evidence; use a new output or --cleanup")
    f = json.loads(args.output.read_text()) if args.cleanup else {
        "service": "stepfunctions", "source": "Native AWS public endpoints through scripts/aws/aws_cli.py",
        "captured_at": now(), "region": args.region, "prefix": "stackd-sfn-ecs-" + uuid.uuid4().hex[:10],
        "documentation": ["https://docs.aws.amazon.com/step-functions/latest/dg/connect-ecs.html"],
        "transport": "AWS CLI modeled outer timestamps; native history/output JSON string bytes retained.",
        "redaction": "Actual task tokens replaced by SHA256-labeled placeholders, including embedded history JSON.",
        "bounds": {"max_executions": 8, "max_tasks": 9, "task_vcpu": 0.25, "task_memory_mib": 512,
                   "execution_timeout_seconds": 240, "task_state_timeout_seconds": 210},
        "resources": {"roles": [], "machines": [], "definitions": []}, "observations": [], "cases": {},
        "cleanup": {}, "limitations": [
            "No EC2 instances, VPCs, subnets, routes, NAT gateways, or load balancers are created; only an owned no-ingress security group uses the existing public subnet.",
            "Placement capacity Failures may not be reachable without EC2/capacity changes; documentation remains authoritative where uncaptured.",
            "No exact fleet latency, billing duration, cross-account or partition claims."],
        "probe_source": {"path": str(Path(__file__)), "text": Path(__file__).read_text()}}
    if args.cleanup and (f.get("account") != args.account or f["region"] != args.region):
        raise RuntimeError("Cleanup account/region differs from requested scope")
    r = f["resources"]
    prefix = f["prefix"]
    secrets = {}

    def discover(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key.lower() == "tasktoken" and isinstance(item, str):
                    secrets[item] = "<redacted-tasktoken-" + hashlib.sha256(item.encode()).hexdigest()[:12] + ">"
                if key in ("Name", "name") and item == "TASK_TOKEN":
                    token = value.get("Value", value.get("value", ""))
                    if token and not token.startswith("<redacted-"):
                        secrets[token] = "<redacted-tasktoken-" + hashlib.sha256(token.encode()).hexdigest()[:12] + ">"
                discover(item)
        elif isinstance(value, list):
            for item in value:
                discover(item)
        elif isinstance(value, str) and value[:1] in ("{", "["):
            try:
                discover(json.loads(value))
            except json.JSONDecodeError:
                pass

    def save():
        discover(f)
        text = json.dumps(f, indent=2)
        for secret, replacement in secrets.items():
            text = text.replace(json.dumps(secret)[1:-1], replacement)
            text = text.replace(json.dumps(json.dumps(secret)[1:-1])[1:-1], replacement)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n")

    def record(label, service, operation, parameters=None):
        started = now()
        result = observe(service, operation, parameters or {}, env)
        f["observations"].append({"label": label, "service": service, "operation": operation,
                                  "input": parameters or {}, "started_at": started, "finished_at": now(), "result": result})
        save()
        print(label + ": " + result["code"], flush=True)
        return result

    def required(label, service, operation, parameters=None):
        result = record(label, service, operation, parameters)
        if result["code"] != "Success":
            raise RuntimeError(label + ": " + json.dumps(result))
        return result["output"]

    def make_role(suffix, principal, statements):
        name = prefix + "-" + suffix
        arn = required("create-role-" + suffix, "iam", "create-role", {
            "RoleName": name, "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}]})})["Role"]["Arn"]
        r["roles"].append(name)
        save()
        required("policy-" + suffix, "iam", "put-role-policy", {"RoleName": name, "PolicyName": "owned",
                 "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": statements})})
        return arn

    def create_machine(label, definition, role):
        result = record("create-machine-" + label, "stepfunctions", "create-state-machine", {
            "name": prefix + "-" + label, "roleArn": role, "definition": json.dumps(definition), "type": "STANDARD"})
        if result["code"] == "Success":
            arn = result["output"]["stateMachineArn"]
            r["machines"].append(arn)
            save()
            return arn
        return None

    def state(resource, parameters):
        return {"StartAt": "Task", "TimeoutSeconds": 240, "States": {"Task": {
            "Type": "Task", "Resource": "arn:aws:states:::ecs:runTask" + resource,
            "Parameters": parameters, "TimeoutSeconds": 210, "End": True}}}

    def run_case(label, resource, parameters, role):
        if len(f["cases"]) >= f["bounds"]["max_executions"]:
            raise RuntimeError("Execution bound reached")
        definition = state(resource, parameters)
        arn = create_machine(label, definition, role)
        if arn is None:
            return
        execution = required(label + "-start", "stepfunctions", "start-execution", {
            "stateMachineArn": arn, "name": label, "input": "{}"})["executionArn"]
        f["cases"][label] = {"executionArn": execution, "definition": definition}
        save()
        return execution

    def finish(label, execution):
        deadline = time.monotonic() + 255
        while True:
            out = required(label + "-describe", "stepfunctions", "describe-execution", {"executionArn": execution})
            if out["status"] != "RUNNING":
                break
            if time.monotonic() >= deadline:
                required(label + "-bounded-stop", "stepfunctions", "stop-execution", {"executionArn": execution, "error": "ProbeDeadline"})
                out = required(label + "-after-stop", "stepfunctions", "describe-execution", {"executionArn": execution})
                break
            time.sleep(4)
        f["cases"][label].update({k: out[k] for k in ("status", "output", "error", "cause") if k in out})
        required(label + "-history", "stepfunctions", "get-execution-history", {"executionArn": execution, "maxResults": 1000})
        save()

    def cleanup():
        for arn in r["machines"]:
            listed = record("cleanup-executions", "stepfunctions", "list-executions", {"stateMachineArn": arn})
            for execution in listed.get("output", {}).get("executions", []):
                if execution["status"] == "RUNNING":
                    record("cleanup-stop-execution", "stepfunctions", "stop-execution", {"executionArn": execution["executionArn"], "error": "ProbeCleanup"})
            record("cleanup-machine", "stepfunctions", "delete-state-machine", {"stateMachineArn": arn})
        if r.get("cluster"):
            for attempt in range(40):
                running = required("cleanup-running-tasks", "ecs", "list-tasks", {"cluster": r["cluster"], "desiredStatus": "RUNNING"})["taskArns"]
                if not running:
                    f["cleanup"]["no_running_tasks"] = True
                    break
                for task in running:
                    record("cleanup-stop-task", "ecs", "stop-task", {"cluster": r["cluster"], "task": task, "reason": "Owned probe cleanup"})
                time.sleep(3)
            stopped = required("cleanup-stopped-tasks", "ecs", "list-tasks", {"cluster": r["cluster"], "desiredStatus": "STOPPED"})["taskArns"]
            if stopped:
                required("cleanup-task-descriptions", "ecs", "describe-tasks", {"cluster": r["cluster"], "tasks": stopped})
            deleted = record("cleanup-cluster", "ecs", "delete-cluster", {"cluster": r["cluster"]})
            f["cleanup"]["cluster_inactive"] = deleted.get("output", {}).get("cluster", {}).get("status") == "INACTIVE"
        for arn in r["definitions"]:
            record("cleanup-deregister-definition", "ecs", "deregister-task-definition", {"taskDefinition": arn})
            deleted = record("cleanup-delete-definition", "ecs", "delete-task-definitions", {"taskDefinitions": [arn]})
            f["cleanup"]["definition_delete_accepted_" + arn] = deleted["code"] == "Success" and not deleted["output"].get("failures")
        for name in r["roles"]:
            record("cleanup-policy", "iam", "delete-role-policy", {"RoleName": name, "PolicyName": "owned"})
            record("cleanup-role", "iam", "delete-role", {"RoleName": name})
            f["cleanup"]["role_absent_" + name] = record("cleanup-role-absent", "iam", "get-role", {"RoleName": name})["code"] == "NoSuchEntity"
        if r.get("security_group"):
            for attempt in range(40):
                deleted = record("cleanup-security-group", "ec2", "delete-security-group", {"GroupId": r["security_group"]})
                if deleted["code"] in ("Success", "InvalidGroup.NotFound"):
                    break
                time.sleep(3)
            f["cleanup"]["security_group_absent"] = record("cleanup-security-group-absent", "ec2", "describe-security-groups", {"GroupIds": [r["security_group"]]})["code"] == "InvalidGroup.NotFound"
        pending = list(r["machines"])
        for attempt in range(60):
            for arn in list(pending):
                if record("cleanup-machine-absent", "stepfunctions", "describe-state-machine", {"stateMachineArn": arn})["code"] == "StateMachineDoesNotExist":
                    pending.remove(arn)
            if not pending:
                break
            time.sleep(3)
        f["cleanup"]["machines_absent"] = not pending
        current = record("cleanup-managed-rule", "events", "describe-rule", {"Name": RULE})
        if current["code"] == "Success" and f.get("managed_rule_owned") and not pending:
            targets = required("cleanup-managed-targets", "events", "list-targets-by-rule", {"Rule": RULE})
            if current["output"].get("ManagedBy") == "states.amazonaws.com" and targets == f.get("managed_targets_created"):
                if targets.get("Targets"):
                    removed = required("cleanup-remove-targets", "events", "remove-targets", {"Rule": RULE, "Ids": [target["Id"] for target in targets["Targets"]], "Force": True})
                    if removed.get("FailedEntryCount"):
                        raise RuntimeError("Managed target cleanup failed")
                required("cleanup-delete-rule", "events", "delete-rule", {"Name": RULE, "Force": True})
        f["cleanup"]["managed_rule_absent"] = record("cleanup-managed-rule-absent", "events", "describe-rule", {"Name": RULE})["code"] == "ResourceNotFoundException"
        f["cleanup_complete"] = all(f["cleanup"].values())
        f["finished_at"] = now()
        save()
        if not f["cleanup_complete"]:
            raise RuntimeError("Incomplete cleanup; inspect capture and resume --cleanup")

    if args.admission_only:
        f["account"] = required("identity", "sts", "get-caller-identity")["Account"]
        f["bounds"].update(max_executions=0, max_tasks=0)
        base = {"Cluster": "probe", "TaskDefinition": "probe:1", "LaunchType": "FARGATE"}
        definitions = {
            "sync-started-by": state(".sync", dict(base, StartedBy="customer-value")),
            "sync-count-path": state(".sync", dict(base, **{"Count.$": "$.count"})),
            "callback-count-two": state(".waitForTaskToken", dict(base, Count=2)),
            "sync-jsonata-count": {"QueryLanguage": "JSONata", "StartAt": "Task", "States": {"Task": {
                "Type": "Task", "Resource": "arn:aws:states:::ecs:runTask.sync", "Arguments": dict(base, Count=2), "End": True}}},
        }
        for label, definition in definitions.items():
            required(label, "stepfunctions", "validate-state-machine-definition", {"definition": json.dumps(definition)})
        f["cleanup_complete"] = True
        f["cleanup"] = {"no_resources_created": True}
        f["finished_at"] = now()
        save()
        return

    if args.api_errors_only:
        f["account"] = required("identity", "sts", "get-caller-identity")["Account"]
        f["bounds"].update(max_executions=0, max_tasks=0)
        f["limitations"] = ["Only one owned short-lived IAM role is created; no task definition, cluster, machine, compute, networking or EventBridge resource is created.",
                            "TestState errors establish only the execution paths actually returned; mock-only patterns are not native service-execution evidence."]
        try:
            missing = prefix + "-missing"
            definition_arn = "arn:aws:ecs:" + args.region + ":" + f["account"] + ":task-definition/" + missing + ":1"
            role = make_role("api-errors", "states.amazonaws.com", [
                {"Effect": "Allow", "Action": "ecs:RunTask", "Resource": definition_arn}])
            time.sleep(12)
            parameters = {"Cluster": missing, "TaskDefinition": definition_arn, "LaunchType": "FARGATE"}
            for label, suffix in (("request-response-missing", ""), ("sync-missing", ".sync"), ("callback-missing", ".waitForTaskToken")):
                definition = state(suffix, parameters)["States"]["Task"]
                record(label, "stepfunctions", "test-state", {
                    "definition": json.dumps(definition), "roleArn": role, "input": "{}", "inspectionLevel": "DEBUG"})
        finally:
            for name in r["roles"]:
                record("cleanup-policy", "iam", "delete-role-policy", {"RoleName": name, "PolicyName": "owned"})
                record("cleanup-role", "iam", "delete-role", {"RoleName": name})
                f["cleanup"]["role_absent_" + name] = record("cleanup-role-absent", "iam", "get-role", {"RoleName": name})["code"] == "NoSuchEntity"
            f["cleanup_complete"] = all(f["cleanup"].values())
            f["finished_at"] = now()
            save()
            if not f["cleanup_complete"]:
                raise RuntimeError("Owned TestState role cleanup failed")
        return

    if args.cleanup:
        cleanup()
        return
    try:
        identity = required("identity", "sts", "get-caller-identity")
        f["account"] = identity["Account"]
        subnet = required("existing-subnet", "ec2", "describe-subnets", {"SubnetIds": [args.subnet]})["Subnets"][0]
        routes = required("existing-routes", "ec2", "describe-route-tables", {"Filters": [{"Name": "association.subnet-id", "Values": [args.subnet]}]})
        if not any(route.get("DestinationCidrBlock") == "0.0.0.0/0" and route.get("GatewayId", "").startswith("igw-") and route.get("State") == "active" for table in routes["RouteTables"] for route in table["Routes"]):
            raise RuntimeError("Existing subnet lacks an explicit active Internet Gateway route")
        before = record("managed-rule-before", "events", "describe-rule", {"Name": RULE})
        if before["code"] != "ResourceNotFoundException":
            raise RuntimeError("Refusing to change an existing shared ECS managed rule")
        f["managed_rule_owned"] = True
        r["security_group"] = required("create-security-group", "ec2", "create-security-group", {"GroupName": prefix, "Description": "Owned bounded Step Functions ECS probe; no inbound rules", "VpcId": subnet["VpcId"]})["GroupId"]
        r["cluster"] = required("create-cluster", "ecs", "create-cluster", {"clusterName": prefix})["cluster"]["clusterArn"]
        save()
        task_role = make_role("task", "ecs-tasks.amazonaws.com", [{"Effect": "Allow", "Action": ["states:SendTaskSuccess", "states:SendTaskFailure"], "Resource": "*"}])
        for label, image, compat, mode in (("good", IMAGE, ["FARGATE"], "awsvpc"), ("bad", "public.ecr.aws/lambda/python:stackd-probe-missing", ["FARGATE"], "awsvpc"), ("ec2", IMAGE, ["EC2"], "bridge")):
            definition = required("register-" + label, "ecs", "register-task-definition", {"family": prefix + "-" + label, "taskRoleArn": task_role,
                "networkMode": mode, "requiresCompatibilities": compat, "cpu": "256", "memory": "512", "containerDefinitions": [
                    {"name": "work", "image": image, "essential": True, "entryPoint": ["/var/lang/bin/python3"], "command": ["-c", "import time;time.sleep(1)"]}]})["taskDefinition"]["taskDefinitionArn"]
            r["definitions"].append(definition)
            r[label + "_definition"] = definition
            save()
        statements = [{"Effect": "Allow", "Action": "ecs:RunTask", "Resource": r["definitions"]},
                      {"Effect": "Allow", "Action": ["ecs:DescribeTasks", "ecs:StopTask"], "Resource": "*"},
                      {"Effect": "Allow", "Action": "iam:PassRole", "Resource": task_role}]
        noevents_role = make_role("noevents", "states.amazonaws.com", statements)
        rule_arn = "arn:aws:events:" + args.region + ":" + f["account"] + ":rule/" + RULE
        full_role = make_role("full", "states.amazonaws.com", statements + [{"Effect": "Allow", "Action": ["events:PutRule", "events:PutTargets", "events:DescribeRule"], "Resource": rule_arn}])
        time.sleep(12)
        base = {"Cluster": r["cluster"], "TaskDefinition": r["good_definition"], "LaunchType": "FARGATE",
                "NetworkConfiguration": {"AwsvpcConfiguration": {"Subnets": [args.subnet], "SecurityGroups": [r["security_group"]], "AssignPublicIp": "ENABLED"}}}
        create_machine("noevents-sync", state(".sync", base), noevents_role)
        # An empty EC2 cluster is a bounded capacity-failure candidate; never register fake instances.
        record("direct-empty-ec2", "ecs", "run-task", {"cluster": r["cluster"], "taskDefinition": r["ec2_definition"], "launchType": "EC2", "count": 1})
        cases = [("request-response-two", "", dict(base, Count=2), noevents_role),
                 ("sync-zero", ".sync", base, full_role),
                 ("sync-nonzero", ".sync", dict(base, Overrides={"ContainerOverrides": [{"Name": "work", "Command": ["-c", "import sys;sys.exit(42)"]}]}), full_role),
                 ("sync-two", ".sync", dict(base, Count=2), full_role),
                 ("sync-start-failure", ".sync", dict(base, TaskDefinition=r["bad_definition"]), full_role)]
        callback_code = "import boto3,os,time;time.sleep(1);boto3.client('stepfunctions',region_name='" + args.region + "').send_task_success(taskToken=os.environ['TASK_TOKEN'],output='\"real-container-callback\"')"
        cases.append(("callback", ".waitForTaskToken", dict(base, Overrides={"ContainerOverrides": [{"Name": "work", "Command": ["-c", callback_code], "Environment": [{"Name": "TASK_TOKEN", "Value.$": "$$.Task.Token"}]}]}), noevents_role))
        started = []
        for label, suffix, params, role in cases:
            execution = run_case(label, suffix, params, role)
            if execution:
                started.append((label, execution))
        f["managed_rule_created"] = record("managed-rule-created", "events", "describe-rule", {"Name": RULE})
        if f["managed_rule_created"]["code"] == "Success":
            f["managed_targets_created"] = required("managed-targets-created", "events", "list-targets-by-rule", {"Rule": RULE})
        for label, execution in started:
            finish(label, execution)
    except Exception:
        f.setdefault("probe_errors", []).append({"at": now(), "traceback": traceback.format_exc()})
        save()
        raise
    finally:
        cleanup()


if __name__ == "__main__":
    main()
