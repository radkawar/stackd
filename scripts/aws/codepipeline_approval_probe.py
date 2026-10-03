#!/usr/bin/env python3
"""Capture owned native CodePipeline Manual/SNS/SQS approval behavior.

One uniquely named V2 pipeline, versioned source bucket, role, SNS topic and SQS
queue; no compute or customer KMS resources. Evidence survives failed captures.
"""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import time
import uuid
import zipfile

import boto3
import botocore
from botocore.config import Config
from botocore.exceptions import ClientError

REGION = "us-east-1"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True, help="Native AWS account ID that must match the STS caller")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--admission-boundaries", action="store_true", help="capture non-executing ARN update admission cases")
    parser.add_argument("--observe-grant-existing", action="store_true", help="only observe whether grant revives a denied action without retry")
    parser.add_argument("--subject-boundaries", action="store_true", help="capture exact-24 pipeline and 24/25 action subjects")
    parser.add_argument("--topic-errors", action="store_true", help="capture FIFO, absent and foreign-topic publication failures")
    parser.add_argument("--cross-account", action="store_true", help="capture current other-profile grant/revoke/absent-topic publication")
    parser.add_argument("--secondary-account", help="Native AWS account ID that must match the 'other' profile STS caller; required with --cross-account")
    parser.add_argument("--summary-requirements", action="store_true", help="capture required-summary approval and rejection behavior")
    args = parser.parse_args()
    if args.cross_account and not args.secondary_account:
        parser.error("--cross-account requires --secondary-account")
    account = args.account
    if args.output.exists():
        raise RuntimeError("Refusing to overwrite native evidence")
    session = boto3.Session(region_name=REGION)
    config = Config(retries={"total_max_attempts": 1}, connect_timeout=10, read_timeout=30,
                    ignore_configured_endpoint_urls=True)
    clients = {name: session.client(name, config=config) for name in ("sts", "iam", "s3", "codepipeline", "sns", "sqs")}
    actor = clients["sts"].get_caller_identity()
    if actor["Account"] != account:
        raise RuntimeError("Refusing non-probe account")
    secondary_actor = None
    if args.cross_account:
        secondary = boto3.Session(profile_name="other", region_name=REGION)
        secondary_actor = secondary.client("sts", config=config).get_caller_identity()
        if secondary_actor["Account"] != args.secondary_account:
            raise RuntimeError("Refusing secondary account other than " + args.secondary_account + ": " + json.dumps(secondary_actor, default=str))
        clients.update({service: secondary.client(service, config=config) for service in ("sns", "sqs")})
    name = "stackd-approval-" + uuid.uuid4().hex[:20]
    owned = {}
    model = session._session.get_component("data_loader").load_service_model("codepipeline", "service-2")
    evidence = {"source": "Native AWS CodePipeline Manual approval SNS notification", "account": account,
                "region": REGION, "actor": actor, "observed_at": datetime.now(timezone.utc).isoformat(),
                "prefix": name, "owned": owned, "calls": [], "snapshots": [], "notifications": [], "cleanup": [],
                "source_model": {"botocore": botocore.__version__, "api_version": model["metadata"]["apiVersion"],
                                 "sha256": hashlib.sha256(json.dumps(model, sort_keys=True).encode()).hexdigest()},
                "references": ["https://docs.aws.amazon.com/codepipeline/latest/userguide/approvals-json-format.html",
                               "https://docs.aws.amazon.com/codepipeline/latest/userguide/approvals.html",
                               "https://docs.aws.amazon.com/sns/latest/dg/subscribe-sqs-queue-to-sns-topic.html"],
                "bounds": {"pipelines": 1, "roles": 1, "buckets": 1, "topics": 1, "queues": 0 if args.topic_errors else 1,
                           "compute": 0, "customer_kms_keys": 0, "state_wait_seconds": 180,
                           "message_wait_seconds": 60, "policy_propagation_seconds": 20},
                "complete": False, "cleanup_verified": False}
    if secondary_actor:
        evidence["secondary_actor"] = secondary_actor
        evidence["secondary_profile"] = "other"
        evidence["client_accounts"] = {service: secondary_actor["Account"] if service in ("sns", "sqs") else account
                                       for service in clients}

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2, default=str) + "\n")

    def call(service, method, parameters, *, label=None, cleanup=False, allowed=("Success",)):
        captured = copy.deepcopy(parameters)
        try:
            output = getattr(clients[service], method)(**parameters)
            metadata = output.pop("ResponseMetadata", {})
            code = "Success"
        except ClientError as error:
            output = error.response["Error"]
            metadata = error.response.get("ResponseMetadata", {})
            code = output["Code"]
        row = {"service": service, "operation": clients[service].meta.method_to_api_mapping[method],
               "label": label or method, "parameters": {k: "<owned ZIP bytes>" if k == "Body" else v for k, v in captured.items()},
               "code": code, "output": output, "request_id": metadata.get("RequestId"),
               "http_status": metadata.get("HTTPStatusCode"), "observed_at": datetime.now(timezone.utc).isoformat()}
        evidence["cleanup" if cleanup else "calls"].append(row)
        save()
        print(row["label"] + ": " + code, flush=True)
        if code not in allowed:
            raise RuntimeError(json.dumps(row, default=str))
        return output

    def action(state, stage):
        return next((a.get("latestExecution", {}) for s in state.get("stageStates", []) if s["stageName"] == stage
                     for a in s.get("actionStates", []) if a["actionName"] == stage), {})

    def wait_state(predicate, label):
        deadline = time.monotonic() + 180
        while True:
            state = call("codepipeline", "get_pipeline_state", {"name": name}, label=label)
            if predicate(state):
                return state
            if time.monotonic() >= deadline:
                raise RuntimeError("Owned pipeline state wait expired: " + label)
            time.sleep(3)

    def snapshot(label, execution):
        state = call("codepipeline", "get_pipeline_state", {"name": name}, label=label + "/state")
        history = call("codepipeline", "list_action_executions", {"pipelineName": name,
                       "filter": {"pipelineExecutionId": execution}}, label=label + "/history")
        run = call("codepipeline", "get_pipeline_execution", {"pipelineName": name,
                   "pipelineExecutionId": execution}, label=label + "/execution")
        evidence["snapshots"].append({"label": label, "execution": execution, "state": state,
                                      "history": history, "pipeline_execution": run})
        save()
        return state, history, run

    def receive(label, required=False):
        deadline = time.monotonic() + (60 if required else 10)
        while True:
            result = call("sqs", "receive_message", {"QueueUrl": owned["queue"], "WaitTimeSeconds": 10,
                          "MaxNumberOfMessages": 10, "MessageSystemAttributeNames": ["All"],
                          "MessageAttributeNames": ["All"]}, label=label)
            notifications = []
            for message in result.get("Messages", []):
                envelope = json.loads(message["Body"])
                inner = json.loads(envelope["Message"])
                row = {"label": label, "sqs_message": message, "sns_envelope": envelope, "inner": inner}
                evidence["notifications"].append(row)
                save()
                print("NOTIFICATION " + json.dumps({"subject": envelope.get("Subject"), "inner": inner}), flush=True)
                call("sqs", "delete_message", {"QueueUrl": owned["queue"], "ReceiptHandle": message["ReceiptHandle"]})
                notifications.append(row)
            if notifications or time.monotonic() >= deadline:
                if required and not notifications:
                    raise RuntimeError("No approval notification within bounded delivery wait")
                return notifications

    def put_policy(mode):
        statements = [{"Effect": "Allow", "Action": "s3:*",
                       "Resource": ["arn:aws:s3:::" + name, "arn:aws:s3:::" + name + "/*"]}]
        if mode != "missing":
            statements.append({"Effect": "Allow" if mode == "allow" else "Deny", "Action": "sns:Publish",
                               "Resource": owned.get("publish_targets", owned["topic"])})
        call("iam", "put_role_policy", {"RoleName": name, "PolicyName": "owned", "PolicyDocument": json.dumps({
             "Version": "2012-10-17", "Statement": statements})}, label="policy/" + mode)
        owned["policy"] = True
        call("iam", "get_role_policy", {"RoleName": name, "PolicyName": "owned"}, label="policy-read/" + mode)
        if mode != "missing":
            time.sleep(20)

    def wait_gate(execution, label):
        return wait_state(lambda state: any(s.get("latestExecution", {}).get("pipelineExecutionId") == execution
                          and s["stageName"] == "Detailed" for s in state.get("stageStates", []))
                          and action(state, "Detailed").get("status") in ("InProgress", "Failed"), label)

    def inspect_denied(execution, label):
        wait_gate(execution, label + "/arrival")
        # Publication failure can be a Failed state projection of a waiting action.
        time.sleep(65)
        state, history, run = snapshot(label, execution)
        messages = receive(label + "/messages")
        evidence[label] = {"latest_action": action(state, "Detailed"), "message_count": len(messages),
                           "pipeline_status": run["pipelineExecution"]["status"]}
        save()
        print("OBSERVATION " + label + " " + json.dumps(evidence[label], default=str), flush=True)
        return state

    def wait_execution(execution, status):
        deadline = time.monotonic() + 180
        while True:
            result = call("codepipeline", "get_pipeline_execution", {"pipelineName": name,
                          "pipelineExecutionId": execution}, label="wait-execution/" + status)
            if result["pipelineExecution"]["status"] == status:
                return
            if time.monotonic() >= deadline:
                raise RuntimeError("Owned execution status wait expired: " + status)
            time.sleep(3)

    def approve_message(execution, stage):
        wait_state(lambda state: action(state, stage).get("status") in ("InProgress", "Failed"), "allowed/" + stage)
        messages = receive("allowed/" + stage + "/message", required=True)
        message = next(row for row in messages if row["inner"]["approval"]["actionName"] == stage)
        state, _, _ = snapshot("before-approve/" + stage, execution)
        payload = message["inner"]["approval"]
        if payload["token"] != action(state, stage).get("token"):
            raise RuntimeError("SNS approval token differs from retained action state")
        call("codepipeline", "put_approval_result", {"pipelineName": name, "stageName": stage, "actionName": stage,
             "token": payload["token"], "result": {"status": "Approved", "summary": "Owned SNS payload approval"}},
             label="approve-payload/" + stage)

    def admission_cases(declaration):
        for label, arn in (
                ("malformed", "not-an-arn"),
                ("wrong-service", owned["topic"].replace(":sns:", ":sqs:")),
                ("other-region", owned["topic"].replace(":us-east-1:", ":us-west-2:")),
                ("other-account", owned["topic"].replace(account, "000000000000")),
                ("fifo-suffix", owned["topic"] + ".fifo"),
                ("missing-topic", owned["topic"] + "-missing"),
                ("restore", owned["topic"])):
            declaration["stages"][1]["actions"][0]["configuration"]["NotificationArn"] = arn
            call("codepipeline", "update_pipeline", {"pipeline": declaration}, label="admission/" + label,
                 allowed=("Success", "InvalidActionDeclarationException", "InvalidStructureException", "ValidationException"))

    def subject_cases(declaration, gate):
        evidence["mode"] = "subject-boundaries"
        pipeline = name[:24]
        declaration["name"] = pipeline
        declaration["stages"] = [declaration["stages"][0], gate("A" * 24), gate("B" * 25)]
        put_policy("allow")
        call("codepipeline", "create_pipeline", {"pipeline": declaration})
        owned["pipeline"] = pipeline
        execution = None
        for size in (24, 25):
            deadline = time.monotonic() + 180
            action_name = ("A" if size == 24 else "B") * size
            while True:
                state = call("codepipeline", "get_pipeline_state", {"name": pipeline}, label="subject/readiness-" + str(size))
                latest = action(state, action_name)
                if latest.get("token"):
                    break
                if latest.get("status") == "Failed":
                    raise RuntimeError("Subject action failed: " + json.dumps(latest, default=str))
                if time.monotonic() >= deadline:
                    raise RuntimeError("Subject action readiness wait expired")
                time.sleep(3)
            messages = receive("subject/action-" + str(size), required=True)
            payload = messages[0]["inner"]["approval"]
            call("codepipeline", "get_pipeline_state", {"name": pipeline}, label="subject/before-approve-" + str(size))
            call("codepipeline", "put_approval_result", {"pipelineName": pipeline, "stageName": payload["stageName"],
                 "actionName": payload["actionName"], "token": payload["token"],
                 "result": {"status": "Approved", "summary": "Owned subject boundary capture"}})
        deadline = time.monotonic() + 180
        while True:
            state = call("codepipeline", "get_pipeline_state", {"name": pipeline}, label="subject/completion")
            execution = state["stageStates"][-1].get("latestExecution", {}).get("pipelineExecutionId")
            if execution:
                run = call("codepipeline", "get_pipeline_execution", {"pipelineName": pipeline, "pipelineExecutionId": execution})
                if run["pipelineExecution"]["status"] == "Succeeded":
                    break
            if time.monotonic() >= deadline:
                raise RuntimeError("Subject-boundary pipeline did not complete")
            time.sleep(3)
        call("codepipeline", "list_action_executions", {"pipelineName": pipeline, "filter": {"pipelineExecutionId": execution}})
        if args.admission_boundaries:
            admission_cases(declaration)
        evidence["complete"] = True
        save()

    def topic_error_cases(declaration):
        evidence["mode"] = "topic-errors"
        targets = {
            "Fifo": owned["topic"],
            "Absent": f"arn:aws:sns:{REGION}:{account}:{name}-missing",
            "Foreign": f"arn:aws:sns:{REGION}:000000000000:{name}-missing",
        }
        owned["publish_targets"] = list(targets.values())
        evidence["topic_error_targets"] = targets
        call("sns", "get_topic_attributes", {"TopicArn": targets["Absent"]}, label="verify-owned-topic-absent", allowed=("NotFound",))
        put_policy("allow")
        declaration["stages"] = [declaration["stages"][0], {"name": "TopicErrors", "actions": [
            {"name": label, "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
             "configuration": {"NotificationArn": arn}, "runOrder": 1} for label, arn in targets.items()]}]
        call("codepipeline", "create_pipeline", {"pipeline": declaration})
        owned["pipeline"] = name
        state = wait_state(lambda state: any(s["stageName"] == "TopicErrors"
                           and len(s.get("actionStates", [])) == 3
                           and all(a.get("latestExecution", {}).get("status") in ("InProgress", "Failed") for a in s["actionStates"])
                           for s in state.get("stageStates", [])), "topic-errors/arrival")
        execution = next(s["latestExecution"]["pipelineExecutionId"] for s in state["stageStates"] if s["stageName"] == "TopicErrors")
        time.sleep(65)
        state, history, run = snapshot("topic-errors/settled", execution)
        evidence["topic_error_results"] = {
            "pipeline_status": run["pipelineExecution"]["status"],
            "state_actions": next(s["actionStates"] for s in state["stageStates"] if s["stageName"] == "TopicErrors"),
            "history_actions": [a for a in history["actionExecutionDetails"] if a["stageName"] == "TopicErrors"],
        }
        evidence["complete"] = True
        save()
        print("TOPIC ERRORS " + json.dumps(evidence["topic_error_results"], default=str), flush=True)

    def cross_account_cases(declaration, role_arn):
        evidence["mode"] = "cross-account-current"
        declaration["stages"] = declaration["stages"][:2]
        original_policy = call("sns", "get_topic_attributes", {"TopicArn": owned["topic"]},
                               label="cross-account/original-topic-policy")["Attributes"]["Policy"]
        granted_policy = json.loads(original_policy)
        granted_policy["Statement"].append({"Sid": "OwnedPrimaryPipelinePublish", "Effect": "Allow",
            "Principal": {"AWS": role_arn}, "Action": "sns:Publish", "Resource": owned["topic"]})
        deadline = time.monotonic() + 60
        while True:
            grant = call("sns", "set_topic_attributes", {"TopicArn": owned["topic"], "AttributeName": "Policy",
                         "AttributeValue": json.dumps(granted_policy)}, label="cross-account/grant-role",
                         allowed=("Success", "InvalidParameter"))
            if "Code" not in grant:
                break
            if "PrincipalNotFound" not in grant.get("Message", "") or time.monotonic() >= deadline:
                raise RuntimeError("Owned cross-account role visibility did not converge: " + json.dumps(grant))
            time.sleep(3)
        call("sns", "get_topic_attributes", {"TopicArn": owned["topic"]}, label="cross-account/granted-topic-policy")
        put_policy("allow")

        def observe(execution, label):
            wait_gate(execution, label + "/arrival")
            time.sleep(65)
            state, _, run = snapshot(label, execution)
            messages = receive(label + "/messages")
            latest = action(state, "Detailed")
            evidence[label] = {"latest_action": latest, "pipeline_status": run["pipelineExecution"]["status"],
                               "notification_count": len(messages)}
            save()
            print("CROSS ACCOUNT " + label + " " + json.dumps(evidence[label], default=str), flush=True)
            if latest.get("token"):
                payload = next((row["inner"]["approval"] for row in messages
                                if row["inner"]["approval"]["token"] == latest["token"]), None)
                if payload:
                    call("codepipeline", "put_approval_result", {"pipelineName": name, "stageName": "Detailed",
                         "actionName": "Detailed", "token": payload["token"],
                         "result": {"status": "Approved", "summary": "Owned cross-account payload approval"}},
                         label=label + "/approve-payload")
                    wait_execution(execution, "Succeeded")
                    snapshot(label + "/approved", execution)
                else:
                    call("codepipeline", "stop_pipeline_execution", {"pipelineName": name,
                         "pipelineExecutionId": execution, "abandon": True, "reason": "Owned cross-account observation complete"})
                    wait_execution(execution, "Stopped")
            elif run["pipelineExecution"]["status"] == "InProgress":
                wait_execution(execution, "Failed")

        call("codepipeline", "create_pipeline", {"pipeline": declaration})
        owned["pipeline"] = name
        state = wait_state(lambda state: any(s["stageName"] == "Detailed" and s.get("latestExecution", {}).get("pipelineExecutionId")
                           for s in state.get("stageStates", [])), "cross-account/initial-execution")
        first = next(s["latestExecution"]["pipelineExecutionId"] for s in state["stageStates"] if s["stageName"] == "Detailed")
        observe(first, "cross-account/granted")
        call("sns", "set_topic_attributes", {"TopicArn": owned["topic"], "AttributeName": "Policy",
             "AttributeValue": original_policy}, label="cross-account/revoke-role")
        call("sns", "get_topic_attributes", {"TopicArn": owned["topic"]}, label="cross-account/revoked-topic-policy")
        time.sleep(20)
        revoked = call("codepipeline", "start_pipeline_execution", {"name": name})["pipelineExecutionId"]
        observe(revoked, "cross-account/revoked")
        absent = owned["topic"] + "-missing"
        call("sns", "get_topic_attributes", {"TopicArn": absent}, label="cross-account/verify-absent", allowed=("NotFound",))
        owned["publish_targets"] = [absent]
        put_policy("allow")
        declaration["stages"][1]["actions"][0]["configuration"]["NotificationArn"] = absent
        call("codepipeline", "update_pipeline", {"pipeline": declaration})
        missing = call("codepipeline", "start_pipeline_execution", {"name": name})["pipelineExecutionId"]
        observe(missing, "cross-account/absent")
        evidence["complete"] = True
        save()

    def summary_cases(declaration, first):
        evidence["mode"] = "summary-requirements"
        evidence["summary_results"] = []
        cases = [
            ("required-empty-approval", "true", "Approved", ""),
            ("required-whitespace-approval", "true", "Approved", "   "),
            ("required-text-approval", "true", "Approved", "Owned review completed"),
            ("required-empty-rejection", "true", "Rejected", ""),
            ("optional-empty-approval", "false", "Approved", ""),
            ("optional-empty-rejection", "false", "Rejected", ""),
        ]
        previous = "true"
        for index, (label, required, status, summary) in enumerate(cases):
            if required != previous:
                declaration["stages"][1]["actions"][0]["configuration"]["IsSummaryRequired"] = required
                call("codepipeline", "update_pipeline", {"pipeline": declaration}, label=label + "/update")
                previous = required
            execution = first if index == 0 else call("codepipeline", "start_pipeline_execution",
                                                     {"name": name}, label=label + "/start")["pipelineExecutionId"]
            state = wait_gate(execution, label + "/arrival")
            latest = action(state, "Detailed")
            if not latest.get("token"):
                raise RuntimeError("Summary case never reached an approval token: " + json.dumps(latest, default=str))
            parameters = {"pipelineName": name, "stageName": "Detailed", "actionName": "Detailed",
                          "token": latest["token"], "result": {"status": status, "summary": summary}}
            result = call("codepipeline", "put_approval_result", parameters, label=label + "/result",
                          allowed=("Success", "ValidationException", "InvalidApprovalTokenException"))
            after = call("codepipeline", "get_pipeline_state", {"name": name}, label=label + "/state")
            evidence["summary_results"].append({"label": label, "required": required, "status": status,
                                               "summary": summary, "result": result,
                                               "action": action(after, "Detailed")})
            save()
            if "Code" in result:
                parameters["result"]["summary"] = "Owned review completed after measured rejection"
                call("codepipeline", "put_approval_result", parameters, label=label + "/finish")
            wait_execution(execution, "Succeeded" if status == "Approved" else "Failed")
            snapshot(label + "/settled", execution)
            receive(label + "/notification", required=True)
        evidence["complete"] = True
        save()

    try:
        role = call("iam", "create_role", {"RoleName": name, "AssumeRolePolicyDocument": json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"},
             "Action": "sts:AssumeRole"}]}), "Tags": [{"Key": "stackd-probe", "Value": name}]})["Role"]
        owned["role"] = name
        put_policy("missing")
        call("s3", "create_bucket", {"Bucket": name}); owned["bucket"] = name
        call("s3", "put_bucket_versioning", {"Bucket": name, "VersioningConfiguration": {"Status": "Enabled"}})
        call("s3", "put_bucket_encryption", {"Bucket": name, "ServerSideEncryptionConfiguration": {
             "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}})
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zipped:
            zipped.writestr("config.json", '{"owned":true}')
        call("s3", "put_object", {"Bucket": name, "Key": "source.zip", "Body": archive.getvalue()})
        if args.topic_errors:
            owned["topic"] = call("sns", "create_topic", {"Name": name + ".fifo",
                                 "Attributes": {"FifoTopic": "true"},
                                 "Tags": [{"Key": "stackd-probe", "Value": name}]})["TopicArn"]
            call("sns", "get_topic_attributes", {"TopicArn": owned["topic"]}, label="verify-owned-fifo-topic")
        else:
            owned["topic"] = call("sns", "create_topic", {"Name": name, "Tags": [{"Key": "stackd-probe", "Value": name}]})["TopicArn"]
            owned["queue"] = call("sqs", "create_queue", {"QueueName": name, "Attributes": {"SqsManagedSseEnabled": "false"},
                                   "tags": {"stackd-probe": name}})["QueueUrl"]
            queue_arn = call("sqs", "get_queue_attributes", {"QueueUrl": owned["queue"], "AttributeNames": ["QueueArn"]})["Attributes"]["QueueArn"]
            call("sqs", "set_queue_attributes", {"QueueUrl": owned["queue"], "Attributes": {"Policy": json.dumps({
                 "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"},
                 "Action": "sqs:SendMessage", "Resource": queue_arn, "Condition": {"ArnEquals": {"aws:SourceArn": owned["topic"]}}}]})}})
            owned["subscription"] = call("sns", "subscribe", {"TopicArn": owned["topic"], "Protocol": "sqs",
                                         "Endpoint": queue_arn, "ReturnSubscriptionArn": True})["SubscriptionArn"]
        def gate(stage, detailed=False):
            configuration = {"NotificationArn": owned["topic"]}
            if detailed:
                configuration.update(CustomData='Review owned source: "ready" & safe', ExternalEntityLink="https://example.com/owned-review?source=zip&check=1")
            return {"name": stage, "actions": [{"name": stage, "actionTypeId": {"category": "Approval", "owner": "AWS",
                    "provider": "Manual", "version": "1"}, "configuration": configuration, "runOrder": 1}]}
        declaration = {"name": name, "roleArn": role["Arn"], "pipelineType": "V2", "executionMode": "QUEUED",
            "artifactStore": {"type": "S3", "location": name}, "stages": [
                {"name": "Source", "actions": [{"name": "Source", "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                 "configuration": {"S3Bucket": name, "S3ObjectKey": "source.zip", "PollForSourceChanges": "false"},
                 "outputArtifacts": [{"name": "SourceZip"}], "runOrder": 1}]}, gate("Detailed", True), gate("Minimal")]}
        if args.cross_account:
            cross_account_cases(declaration, role["Arn"])
            return
        if args.topic_errors:
            topic_error_cases(declaration)
            return
        if args.subject_boundaries:
            subject_cases(declaration, gate)
            return
        if args.summary_requirements:
            declaration["stages"] = declaration["stages"][:2]
            declaration["stages"][1]["actions"][0]["configuration"]["IsSummaryRequired"] = "true"
            put_policy("allow")
        deadline = time.monotonic() + 60
        while True:
            result = call("codepipeline", "create_pipeline", {"pipeline": declaration}, allowed=("Success", "InvalidStructureException"))
            if "Code" not in result:
                break
            if "not authorized to perform AssumeRole" not in result.get("Message", "") or time.monotonic() >= deadline:
                raise RuntimeError(json.dumps(result))
            time.sleep(3)
        owned["pipeline"] = name
        state = wait_state(lambda state: any(s["stageName"] == "Detailed" and s.get("latestExecution", {}).get("pipelineExecutionId")
                           for s in state.get("stageStates", [])), "initial-execution")
        first = next(s["latestExecution"]["pipelineExecutionId"] for s in state["stageStates"] if s["stageName"] == "Detailed")
        evidence["first_execution"] = first
        if args.summary_requirements:
            summary_cases(declaration, first)
            return
        state = inspect_denied(first, "missing_publish")
        if args.observe_grant_existing:
            evidence["mode"] = "grant-existing-without-retry"
            put_policy("allow")
            time.sleep(65)
            snapshot("grant-existing-without-retry", first)
            receive("grant-existing-without-retry/messages")
            evidence["complete"] = True
            save()
            return
        denied_token = action(state, "Detailed")["actionExecutionId"]
        hidden_approval = call("codepipeline", "put_approval_result", {"pipelineName": name, "stageName": "Detailed",
                               "actionName": "Detailed", "token": denied_token,
                               "result": {"status": "Approved", "summary": "Owned action ID token while SNS denied"}},
                               label="missing-publish/approve-action-id",
                               allowed=("Success", "InvalidApprovalTokenException", "ApprovalAlreadyCompletedException"))
        evidence["missing_publish_action_id_approval"] = hidden_approval
        if "Code" not in hidden_approval:
            wait_state(lambda state: action(state, "Minimal").get("status") in ("InProgress", "Failed"),
                       "missing-publish/after-action-id-approval")
        snapshot("missing-publish-after-action-id-approval", first)
        put_policy("allow")
        retry = call("codepipeline", "retry_stage_execution", {"pipelineName": name, "pipelineExecutionId": first,
                     "stageName": "Detailed", "retryMode": "FAILED_ACTIONS"},
                     allowed=("Success", "StageNotRetryableException"))
        snapshot("permission-granted-retry-result", first)
        if retry.get("Code") == "StageNotRetryableException":
            call("codepipeline", "stop_pipeline_execution", {"pipelineName": name, "pipelineExecutionId": first, "abandon": True,
                 "reason": "Owned missing-publish observation complete"})
            wait_execution(first, "Stopped")
            allowed_execution = call("codepipeline", "start_pipeline_execution", {"name": name})["pipelineExecutionId"]
        else:
            allowed_execution = first
        evidence["allowed_execution"] = allowed_execution
        wait_gate(allowed_execution, "allowed-arrival")
        approve_message(allowed_execution, "Detailed")
        approve_message(allowed_execution, "Minimal")
        wait_state(lambda state: action(state, "Minimal").get("status") == "Succeeded", "allowed-completion")
        wait_execution(allowed_execution, "Succeeded")
        snapshot("approved-success", allowed_execution)
        put_policy("deny")
        denied = call("codepipeline", "start_pipeline_execution", {"name": name})["pipelineExecutionId"]
        evidence["denied_execution"] = denied
        inspect_denied(denied, "current_publish_denied")
        if args.admission_boundaries:
            if evidence["current_publish_denied"]["pipeline_status"] == "InProgress":
                call("codepipeline", "stop_pipeline_execution", {"pipelineName": name, "pipelineExecutionId": denied,
                     "abandon": True, "reason": "Owned declaration-only admission capture"})
                wait_execution(denied, "Stopped")
            admission_cases(declaration)
        evidence["complete"] = True
    except BaseException as error:
        evidence["failure"] = {"type": type(error).__name__, "message": str(error)}
        save()
        raise
    finally:
        failures = []
        def remove(service, method, parameters, allowed=("Success",)):
            try:
                return call(service, method, parameters, cleanup=True, allowed=allowed)
            except Exception as error:
                failures.append(str(error))
                return {}
        if owned.get("pipeline"):
            remove("codepipeline", "delete_pipeline", {"name": owned["pipeline"]})
            remove("codepipeline", "get_pipeline", {"name": owned["pipeline"]}, ("PipelineNotFoundException",))
        if owned.get("subscription"):
            remove("sns", "unsubscribe", {"SubscriptionArn": owned["subscription"]})
            remove("sns", "get_subscription_attributes", {"SubscriptionArn": owned["subscription"]}, ("NotFound",))
        if owned.get("topic"):
            remove("sns", "delete_topic", {"TopicArn": owned["topic"]})
            remove("sns", "get_topic_attributes", {"TopicArn": owned["topic"]}, ("NotFound",))
        if owned.get("queue"):
            remove("sqs", "delete_queue", {"QueueUrl": owned["queue"]})
            remove("sqs", "get_queue_url", {"QueueName": name}, ("AWS.SimpleQueueService.NonExistentQueue",))
        if owned.get("bucket"):
            versions = remove("s3", "list_object_versions", {"Bucket": name})
            if versions.get("IsTruncated"):
                failures.append("Unexpected version inventory exceeds bounded probe")
            objects = [{"Key": row["Key"], "VersionId": row["VersionId"]} for kind in ("Versions", "DeleteMarkers") for row in versions.get(kind, [])]
            if objects:
                result = remove("s3", "delete_objects", {"Bucket": name, "Delete": {"Objects": objects}})
                if result.get("Errors"):
                    failures.append(json.dumps(result["Errors"]))
            remove("s3", "delete_bucket", {"Bucket": name})
            remove("s3", "head_bucket", {"Bucket": name}, ("404",))
        if owned.get("policy"):
            remove("iam", "delete_role_policy", {"RoleName": name, "PolicyName": "owned"})
        if owned.get("role"):
            remove("iam", "delete_role", {"RoleName": name})
            remove("iam", "get_role", {"RoleName": name}, ("NoSuchEntity",))
        evidence["cleanup_verified"] = not failures
        evidence["cleanup_errors"] = failures
        save()
        if failures:
            raise RuntimeError("Owned cleanup failed: " + json.dumps(failures))
    print(json.dumps({"output": str(args.output), "complete": evidence["complete"], "cleanup_verified": evidence["cleanup_verified"]}))


if __name__ == "__main__":
    main()
