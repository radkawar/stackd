#!/usr/bin/env python3
"""Reviewed exact-owned native alarm process survival and poll-failure evidence."""
import argparse
import copy
from pathlib import Path
import signal
import time

from ssm_alarms_probe import Alarms
from ssm_managed_execution_probe import interrupt, now


class Lifecycle(Alarms):
    def setup_alarms(self):
        self.call("existing-monitor-role", "iam", "get_role", {"RoleName": "AWSServiceRoleForAmazonSSM"}, required=True)
        self.data["bounds"].update(max_commands=12, max_calls=1000)
        for label in ("trigger", "missing-false", "missing-true"):
            name = self.data["prefix"] + "-" + label
            out = self.call("alarm-absent", "cloudwatch", "describe_alarms", {"AlarmNames": [name]}, required=True)
            assert not out.get("MetricAlarms") and not out.get("CompositeAlarms")
            self.own("alarms", name)
            self.save()
            self.call("alarm-create", "cloudwatch", "put_metric_alarm", {"AlarmName": name, "Namespace": self.data["prefix"], "MetricName": "probe", "ComparisonOperator": "GreaterThanThreshold", "Threshold": 1, "EvaluationPeriods": 1, "Period": 86400, "Statistic": "Sum", "TreatMissingData": "ignore", "ActionsEnabled": False, "Tags": [{"Key": "suite", "Value": self.data["prefix"]}]}, required=True)
            self.state(name, "OK")

    def exercise(self, first, second):
        self.wait_ready(first)
        self.wait_ready(second)
        for index, label in enumerate(("trigger", "missing-false", "missing-true")):
            name = self.data["owned"]["alarms"][index]
            marker = "/var/tmp/" + name
            script = "printf 'started\\n' > " + marker + "; sleep 100; printf 'finished\\n' >> " + marker
            cid = self.submit(label, [first, second], {"Alarms": [{"Name": name}], "IgnorePollAlarmFailure": label == "missing-true"}, script=script, MaxConcurrency="1")
            assert cid
            active = self.poll(label + "-active", "ssm", "list_command_invocations", {"CommandId": cid, "Details": True}, lambda r: any(i["Status"] == "InProgress" for i in r.get("CommandInvocations", [])), seconds=60, interval=2)
            assert active
            changed_at = time.monotonic()
            if label == "trigger":
                self.state(name, "ALARM")
            else:
                self.call(label + "-delete-alarm", "cloudwatch", "delete_alarms", {"AlarmNames": [name]}, required=True)
            self.finish(label, cid, seconds=300)
            time.sleep(max(0, 110 - (time.monotonic() - changed_at)))
            readback = self.ssm(label + "-read-marker", "send_command", {"DocumentName": "AWS-RunShellScript", "InstanceIds": [first, second], "Parameters": {"commands": ["if test -f " + marker + "; then cat " + marker + "; else printf 'marker-absent\\n'; fi"], "executionTimeout": ["30"]}, "TimeoutSeconds": 30}, required=True)["Command"]["CommandId"]
            self.finish(label + "-readback", readback)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    args.endpoint, args.live_seconds = None, 1800
    cap = Lifecycle(args)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
        signal.signal(sig, interrupt)
    try:
        if not args.cleanup_only:
            signal.alarm(args.live_seconds)
            cap.setup_alarms()
            first = cap.setup_native()
            request = copy.deepcopy(next(r["input"] for r in cap.data["calls"] if r["operation"] == "RunInstances" and r["code"] == "Success"))
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
    print(args.output)


if __name__ == "__main__":
    main()
