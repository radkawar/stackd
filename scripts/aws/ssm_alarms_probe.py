#!/usr/bin/env python3
"""Reviewed bounded native Run Command alarm calibration, exact-owned resources."""
import argparse
import copy
import json
from pathlib import Path
import signal
import time

from botocore.config import Config
from ssm_managed_execution_probe import Capture, REGION, interrupt, now, TERMINAL

CONFIG = Config(retries={"max_attempts": 0}, connect_timeout=5, read_timeout=20, parameter_validation=False)


class Alarms(Capture):
    def __init__(self, args):
        super().__init__(args)
        for name in ("cloudwatch", "ssm"):
            self.clients[name] = self.session.client(name, config=CONFIG)
        self.data["bounds"].update(max_instances=2, public_ipv4=2, max_commands=35, max_calls=1400)
        self.save()

    def call(self, *args, **kwargs):
        if not self.cleaning and len(self.data["calls"]) >= self.data["bounds"]["max_calls"] - 150:
            raise RuntimeError("Live call bound reached; preserving cleanup capacity")
        kwargs["throttle_attempt"] = 3
        return super().call(*args, **kwargs)

    def state(self, name, state):
        self.call("alarm-state-" + state, "cloudwatch", "set_alarm_state", {"AlarmName": name, "StateValue": state, "StateReason": "Exact-owned SSM alarm calibration"}, required=True)
        self.call("alarm-state-observe", "cloudwatch", "describe_alarms", {"AlarmNames": [name]}, required=True)

    def setup_alarms(self):
        # Monitoring may auto-provision this account-wide role. Require it to
        # exist so an exact-owned experiment never creates standing IAM state.
        self.call("existing-monitor-role", "iam", "get_role", {"RoleName": "AWSServiceRoleForAmazonSSM"}, required=True)
        p = self.data["prefix"]
        for suffix in ("control", "trigger"):
            name = p + "-" + suffix
            out = self.call("alarm-absent", "cloudwatch", "describe_alarms", {"AlarmNames": [name]}, required=True)
            assert not out.get("MetricAlarms") and not out.get("CompositeAlarms")
            self.own("alarms", name)
            self.save()
            self.call("alarm-create", "cloudwatch", "put_metric_alarm", {"AlarmName": name, "Namespace": p, "MetricName": "probe", "ComparisonOperator": "GreaterThanThreshold", "Threshold": 1, "EvaluationPeriods": 1, "Period": 86400, "Statistic": "Sum", "TreatMissingData": "ignore", "ActionsEnabled": False, "Tags": [{"Key": "suite", "Value": p}]}, required=True)
        role = p + "-caller"
        self.call("caller-absent", "iam", "get_role", {"RoleName": role})
        assert self.data["calls"][-1]["code"] == "NoSuchEntity"
        self.data["owned"]["caller_role"] = role
        self.save()
        result = self.call("caller-create", "iam", "create_role", {"RoleName": role, "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": self.data["identity"]["Arn"]}, "Action": "sts:AssumeRole"}]})}, required=True)
        self.data["caller_arn"] = result["Role"]["Arn"]
        self.caller_policy(False)

    def caller_policy(self, cloudwatch):
        actions = ["ssm:SendCommand", "ssm:ListCommands", "ssm:ListCommandInvocations", "ssm:GetCommandInvocation"]
        if cloudwatch:
            actions += ["cloudwatch:DescribeAlarms"]
        self.call("caller-policy-" + str(cloudwatch), "iam", "put_role_policy", {"RoleName": self.data["owned"]["caller_role"], "PolicyName": "probe", "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]})}, required=True)

    def submit(self, label, ids, config, script="printf 'alarm-eligible\\n'", client=None, **extra):
        params = {"DocumentName": "AWS-RunShellScript", "InstanceIds": ids, "Parameters": {"commands": [script], "executionTimeout": ["300"]}, "TimeoutSeconds": 60, "Comment": label, "AlarmConfiguration": config, **extra}
        result = self.ssm(label, "send_command", params, client=client)
        return result.get("Command", {}).get("CommandId")

    def finish(self, label, cid, seconds=180):
        if not cid:
            return
        self.poll(label + "-terminal", "ssm", "list_commands", {"CommandId": cid}, lambda r: bool(r.get("Commands")) and r["Commands"][0]["Status"] in TERMINAL, seconds=seconds, interval=3)
        self.ssm(label + "-invocations", "list_command_invocations", {"CommandId": cid, "Details": True})

    def exercise(self, first, second):
        self.wait_ready(first)
        self.wait_ready(second)
        control, trigger = self.data["owned"]["alarms"]
        config = {"Alarms": [{"Name": control}]}
        invalid = [("empty", {}), ("zero", {"Alarms": []}), ("two", {"Alarms": [{"Name": control}, {"Name": trigger}]}), ("empty-name", {"Alarms": [{"Name": ""}]}), ("long-name", {"Alarms": [{"Name": "x" * 256}]}), ("space-name", {"Alarms": [{"Name": " "}]}), ("missing-name", {"Alarms": [{}]})]
        for label, value in invalid:
            cid = self.submit(label, [first], value)
            self.finish(label, cid)
        for state in ("OK", "INSUFFICIENT_DATA", "ALARM"):
            self.state(control, state)
            for ignore in (False, True):
                label = state + "-ignore-" + str(ignore)
                cid = self.submit(label, [first], {**config, "IgnorePollAlarmFailure": ignore})
                self.finish(label, cid)
        for ignore in (False, True):
            label = "missing-ignore-" + str(ignore)
            cid = self.submit(label, [first], {"Alarms": [{"Name": control + "-absent"}], "IgnorePollAlarmFailure": ignore})
            self.finish(label, cid)
        self.state(control, "OK")
        credentials = self.clients["sts"].assume_role(RoleArn=self.data["caller_arn"], RoleSessionName="alarm-probe")["Credentials"]
        client = self.session.client("ssm", config=CONFIG, aws_access_key_id=credentials["AccessKeyId"], aws_secret_access_key=credentials["SecretAccessKey"], aws_session_token=credentials["SessionToken"])
        for ignore in (False, True):
            label = "caller-no-cloudwatch-" + str(ignore)
            cid = self.submit(label, [first], {**config, "IgnorePollAlarmFailure": ignore}, client=client)
            self.finish(label, cid)
        self.caller_policy(True)
        time.sleep(15)
        cid = self.submit("caller-with-cloudwatch", [first], config, client=client)
        self.finish("caller-with-cloudwatch", cid)
        self.state(trigger, "OK")
        cid = self.submit("active-and-pending-trigger", [first, second], {"Alarms": [{"Name": trigger}]}, script="printf 'before-alarm\\n'; sleep 120; printf 'after-alarm\\n'", MaxConcurrency="1")
        if cid:
            self.poll("trigger-active", "ssm", "list_command_invocations", {"CommandId": cid, "Details": True}, lambda r: any(i["Status"] == "InProgress" for i in r.get("CommandInvocations", [])), seconds=60, interval=2)
            self.state(trigger, "ALARM")
            self.finish("active-and-pending-trigger", cid, seconds=300)
        self.state(control, "OK")
        cid = self.submit("current-caller-policy-revoked", [first, second], config, script="printf 'before-revoke\\n'; sleep 120; printf 'after-revoke\\n'", client=client, MaxConcurrency="1")
        if cid:
            self.poll("revoke-active", "ssm", "list_command_invocations", {"CommandId": cid, "Details": True}, lambda r: any(i["Status"] == "InProgress" for i in r.get("CommandInvocations", [])), seconds=60, interval=2)
            self.caller_policy(False)
            self.finish("current-caller-policy-revoked", cid, seconds=300)

    def cleanup(self):
        signal.alarm(0)
        self.cleaning = True
        self.cleanup_deadline = time.monotonic() + 600
        o = self.data["owned"]
        proof = self.data.setdefault("alarm_cleanup", {})
        try:
            if o.get("alarms"):
                self.call("cleanup-alarms", "cloudwatch", "delete_alarms", {"AlarmNames": o["alarms"]})
                result = self.call("cleanup-alarms-absence", "cloudwatch", "describe_alarms", {"AlarmNames": o["alarms"]}, required=True)
                proof["alarms"] = not result.get("MetricAlarms") and not result.get("CompositeAlarms")
            if o.get("caller_role"):
                self.call("cleanup-caller-policy", "iam", "delete_role_policy", {"RoleName": o["caller_role"], "PolicyName": "probe"})
                self.call("cleanup-caller", "iam", "delete_role", {"RoleName": o["caller_role"]})
                self.call("cleanup-caller-absence", "iam", "get_role", {"RoleName": o["caller_role"]})
                proof["caller"] = self.data["calls"][-1]["code"] == "NoSuchEntity"
            self.save()
        finally:
            super().cleanup()
        assert all(proof.values()), proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    args.endpoint, args.live_seconds = None, 2400
    cap = Alarms(args)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
        signal.signal(sig, interrupt)
    try:
        if not args.cleanup_only:
            signal.alarm(args.live_seconds)
            cap.setup_alarms()
            first = cap.setup_native()
            request = copy.deepcopy(next(row["input"] for row in cap.data["calls"] if row["operation"] == "RunInstances" and row["code"] == "Success"))
            request["ClientToken"] += "-second"
            second = cap.call("launch-second-owned-node", "ec2", "run_instances", request, required=True)["Instances"][0]["InstanceId"]
            cap.exercise(first, second)
            cap.data["experiment_complete"] = True
            cap.save()
    except Exception as error:
        cap.data["fatal"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        cap.save()
        raise
    finally:
        cap.cleanup()
    print(json.dumps({"evidence": str(args.output), "cleanup": cap.data["cleanup"]["complete"], "alarms": cap.data["alarm_cleanup"]}))


if __name__ == "__main__":
    main()
