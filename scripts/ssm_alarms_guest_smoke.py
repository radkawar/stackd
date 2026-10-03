#!/usr/bin/env python3
"""Run Command alarms through current CloudWatch, IAM and two official SSM agents.

Reuses the immutable image/package and cleanup workflow; no native AWS calls,
controller state edits, fake pollers, or injected agent replies.
"""
import copy
from datetime import datetime, timezone
import json
import ssl
import time
import urllib.request

from botocore.exceptions import ClientError

import ssm_managed_guest_smoke as guest
from ssm_notifications_guest_smoke import NotificationSmoke


class AlarmSmoke(NotificationSmoke):
    def send(self, label, commands, **options):
        cid = super().send(label, commands, **options)
        self.owned.setdefault("alarm_commands", []).append(cid)
        self.save()
        return cid

    def alarm(self, suffix, state="OK"):
        name = self.prefix + "-" + suffix
        self.call("create-alarm-" + suffix, "cloudwatch", "put_metric_alarm", AlarmName=name, Namespace=self.prefix, MetricName="health", ComparisonOperator="GreaterThanThreshold", Threshold=1, EvaluationPeriods=1, Period=86400, Statistic="Sum", TreatMissingData="ignore", ActionsEnabled=False)
        if name not in self.owned.setdefault("alarms", []):
            self.owned["alarms"].append(name)
        self.save()
        self.set_alarm_state(name, state)
        return name

    def set_alarm_state(self, name, state):
        self.call("set-alarm-" + state, "cloudwatch", "set_alarm_state", AlarmName=name, StateValue=state, StateReason="Official-agent alarm consumer smoke")
        result = self.call("read-current-alarm", "cloudwatch", "describe_alarms", AlarmNames=[name])
        assert result["MetricAlarms"][0]["StateValue"] == state, result

    def config(self, name, ignore=False):
        return {"Alarms": [{"Name": name}], "IgnorePollAlarmFailure": ignore}

    def finish_all(self, label, cid, status, details=None, seconds=120):
        result = self.wait(label, lambda: self.client("ssm").list_commands(CommandId=cid), lambda r: r["Commands"][0]["Status"] in guest.TERMINAL, seconds)
        command = self.call(label + "-command", "ssm", "list_commands", CommandId=cid)["Commands"][0]
        invocations = self.call(label + "-invocations", "ssm", "list_command_invocations", CommandId=cid, Details=True)["CommandInvocations"]
        assert command["Status"] == status and (details is None or command["StatusDetails"] == details), command
        self.data["observations"][label] = {"command": command, "invocations": invocations}
        self.save()
        return command, invocations

    def start_second(self):
        request = copy.deepcopy(next(r["input"] for r in self.data["calls"] if r["label"] == "launch-real-guest"))
        second = self.call("launch-second-official-agent", "ec2", "run_instances", **request)["Instances"][0]["InstanceId"]
        self.owned["second_instance"] = second
        self.save()
        try:
            # Disk materialization is a separate EC2 transition; its wall time
            # must not consume the official agent's registration deadline.
            running = self.wait("second guest reaches running", lambda: self.client("ec2").describe_instances(InstanceIds=[second]), lambda r: r["Reservations"][0]["Instances"][0]["State"]["Name"] in ("running", "stopped", "terminated"), 600, 5)
            assert running["Reservations"][0]["Instances"][0]["State"]["Name"] == "running", running
            self.wait("second official agent registers", lambda: self.client("ssm").describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [second]}]), lambda r: r["InstanceInformationList"] and r["InstanceInformationList"][0]["PingStatus"] == "Online", 240, 2)
        except BaseException:
            self.call("failure-second-real-console", "ec2", "get_console_output", InstanceId=second, Latest=True)
            raise
        finally:
            instance = self.call("read-second-guest-attachments", "ec2", "describe_instances", InstanceIds=[second])["Reservations"][0]["Instances"][0]
            self.owned["volumes"] += [v["Ebs"]["VolumeId"] for v in instance.get("BlockDeviceMappings", [])]
            self.owned["enis"] += [v["NetworkInterfaceId"] for v in instance.get("NetworkInterfaces", [])]
            self.save()

    def exercise(self):
        self.setup_notifications()
        self.start_second()
        ids = [self.owned["instance"], self.owned["second_instance"]]
        guard = self.alarm("guard")
        for state in ("OK", "INSUFFICIENT_DATA"):
            self.set_alarm_state(guard, state)
            cid = self.send("eligible-" + state, ["printf actual-alarm-agent"], AlarmConfiguration=self.config(guard), ServiceRoleArn=self.notification_role, NotificationConfig={"NotificationArn": self.owned["notification_topic"], "NotificationType": "Invocation", "NotificationEvents": ["All"]})
            self.data["notification_cases"][cid] = {"label": state, "type": "Invocation", "events": ["All"]}
            self.save()
            out = self.result("eligible-" + state, cid)
            assert out["Status"] == "Success" and out["StandardOutputContent"] == "actual-alarm-agent", out
            self.await_notifications(cid, ["InProgress", "Success"])
        self.set_alarm_state(guard, "ALARM")
        for ignore in (False, True):
            self.expect("reject-initial-alarm-" + str(ignore), "ValidationException", "ssm", "send_command", DocumentName="AWS-RunShellScript", InstanceIds=ids, Parameters={"commands": ["printf must-not-run"]}, AlarmConfiguration=self.config(guard, ignore))
        self.set_alarm_state(guard, "OK")
        marker = "/var/tmp/" + self.prefix + "-alarm-marker"
        script = "printf 'started\\n' > " + marker + "; sleep 35; printf 'finished\\n' >> " + marker
        triggered = self.send("active-and-pending", [script], InstanceIds=ids, Parameters={"commands": [script], "executionTimeout": ["90"]}, MaxConcurrency="1", AlarmConfiguration=self.config(guard))
        active = self.wait("one active one pending", lambda: self.client("ssm").list_command_invocations(CommandId=triggered), lambda r: sorted(i["Status"] for i in r["CommandInvocations"]) == ["InProgress", "Pending"], 60)
        active_id = next(i["InstanceId"] for i in active["CommandInvocations"] if i["Status"] == "InProgress")
        witness = self.send("witness-real-running-marker", ["for i in $(seq 1 20); do test -f " + marker + " && { cat " + marker + "; exit; }; sleep 1; done; exit 1"], InstanceIds=[active_id])
        _, witness_invs = self.finish_all("witness-running", witness, "Success")
        assert witness_invs[0]["CommandPlugins"][0]["Output"] == "started\n", witness_invs
        self.set_alarm_state(guard, "ALARM")
        command, invocations = self.finish_all("triggered-pending-stop", triggered, "Failed", "FailedDueToAlarm")
        assert command["TriggeredAlarms"] == [{"Name": guard, "State": "ALARM"}] and command["ErrorCount"] == 0, command
        assert all(i["Status"] == "Failed" and i["StatusDetails"] == "Terminated" and i["CommandPlugins"][0]["ResponseCode"] == -1 for i in invocations), invocations
        time.sleep(36)
        readback = self.send("verify-running-survival-pending-absence", ["if test -f " + marker + "; then cat " + marker + "; else printf 'marker-absent\\n'; fi"], InstanceIds=ids)
        _, rows = self.finish_all("running-survival-pending-absence", readback, "Success")
        outputs = {i["InstanceId"]: i["CommandPlugins"][0]["Output"] for i in rows}
        assert outputs[active_id] == "started\nfinished\n" and sorted(outputs.values()) == ["marker-absent\n", "started\nfinished\n"], outputs
        missing = self.prefix + "-missing"
        self.expect("reject-missing-alarm", "ValidationException", "ssm", "send_command", DocumentName="AWS-RunShellScript", InstanceIds=ids, Parameters={"commands": ["printf forbidden"]}, AlarmConfiguration=self.config(missing))
        cid = self.send("ignore-missing-executes", ["printf ignore-poll-failure-executed"], AlarmConfiguration=self.config(missing, True))
        assert self.result("ignore-missing-executes", cid)["StandardOutputContent"] == "ignore-poll-failure-executed"
        ignored = self.alarm("ignored-live-deletion")
        script = "sleep 8; printf ignored-live-delete"
        cid = self.send("ignore-live-alarm-deletion", [script], InstanceIds=ids, Parameters={"commands": [script], "executionTimeout": ["90"]}, MaxConcurrency="1", AlarmConfiguration=self.config(ignored, True))
        self.wait("ignored deletion active", lambda: self.client("ssm").list_command_invocations(CommandId=cid), lambda r: any(i["Status"] == "InProgress" for i in r["CommandInvocations"]), 60)
        self.call("delete-ignored-live-alarm", "cloudwatch", "delete_alarms", AlarmNames=[ignored])
        command, rows = self.finish_all("ignored-live-deletion-completes-both", cid, "Success")
        assert not command.get("TriggeredAlarms") and all(i["CommandPlugins"][0]["Output"] == "ignored-live-delete" for i in rows), (command, rows)
        # The unresolved monitor remains a real scheduled owner over process restart.
        script = "sleep 45; printf recovered-alarm-must-stop-pending"
        retained = self.send("retain-ignored-monitor", [script], InstanceIds=ids, Parameters={"commands": [script], "executionTimeout": ["90"]}, MaxConcurrency="1", AlarmConfiguration=self.config(missing, True))
        self.wait("retained actual agent active", lambda: self.client("ssm").list_command_invocations(CommandId=retained), lambda r: any(i["Status"] == "InProgress" for i in r["CommandInvocations"]), 60)
        self.stop()
        self.start()
        restored = self.alarm("missing", "ALARM")
        command, _ = self.finish_all("retained-monitor-recovery", retained, "Failed", "FailedDueToAlarm")
        assert command["TriggeredAlarms"] == [{"Name": restored, "State": "ALARM"}], command
        deleted = self.alarm("deleted")
        script = "sleep 30; printf deleted-alarm-active"
        cid = self.send("poll-current-deleted-alarm", [script], InstanceIds=ids, Parameters={"commands": [script], "executionTimeout": ["90"]}, MaxConcurrency="1", AlarmConfiguration=self.config(deleted))
        self.wait("deletion actual agent active", lambda: self.client("ssm").list_command_invocations(CommandId=cid), lambda r: any(i["Status"] == "InProgress" for i in r["CommandInvocations"]), 60)
        self.call("delete-current-monitored-alarm", "cloudwatch", "delete_alarms", AlarmNames=[deleted])
        command, _ = self.finish_all("current-poll-failure-stops", cid, "Failed", "FailedDueToUnknownAlarmState")
        assert command["TriggeredAlarms"] == [{"Name": deleted, "State": "UNKNOWN"}], command
        self.data["observations"]["alarm-proof"] = {"official_agents": ids, "sqlite_restart": True, "native_process_survival": True, "pending_guest_marker_absent": True, "current_cloudwatch": True, "notifications_preserved": True}
        self.save()

    def cleanup(self):
        errors, proof = [], {}
        if self.process is not None:
            for cid in self.owned.get("alarm_commands", []):
                try:
                    self.call("settle-owned-command", "ssm", "cancel_command", CommandId=cid)
                except Exception as error:
                    errors.append(str(error))
            if self.owned.get("alarms"):
                try:
                    self.call("cleanup-alarms", "cloudwatch", "delete_alarms", AlarmNames=self.owned["alarms"])
                    out = self.call("absence-alarms", "cloudwatch", "describe_alarms", AlarmNames=self.owned["alarms"])
                    proof["alarms"] = not out.get("MetricAlarms") and not out.get("CompositeAlarms")
                except Exception as error:
                    errors.append(str(error))
            if self.owned.get("second_instance"):
                try:
                    self.call("terminate-second-guest", "ec2", "terminate_instances", InstanceIds=[self.owned["second_instance"]])
                    out = self.wait("second guest terminated", lambda: self.client("ec2").describe_instances(InstanceIds=[self.owned["second_instance"]]), lambda r: r["Reservations"][0]["Instances"][0]["State"]["Name"] == "terminated", 120)
                    proof["second_guest_terminated"] = out["Reservations"][0]["Instances"][0]["State"]["Name"] == "terminated"
                except Exception as error:
                    errors.append(str(error))
        self.data["alarm_cleanup"] = {"absent": proof, "errors": errors}
        self.save()
        try:
            super().cleanup()
        except Exception as error:
            errors.append(str(error))
        # IAM deliberately protects live service-role sessions even after the
        # command's resource usage clears. Only after actual guest/resource
        # teardown, reopen the supported manual timeline and expire those owned
        # sessions through the public clock control; never alter credential rows.
        if self.data.get("cleanup", {}).get("resource_deletes_completed") and self.owned.get("alarm_commands"):
            try:
                self.controller_args = ["-clock-start", datetime.now(timezone.utc).isoformat()]
                self.start()
                request = urllib.request.Request(self.endpoint + "/_stackd/clock", data=json.dumps({"advance": "2h"}).encode(), headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(request, context=ssl.create_default_context(cafile=str(self.state / "server.crt")), timeout=30) as response:
                    self.data["alarm_cleanup"]["session_expiry_clock"] = json.load(response)
                self.save()
                try:
                    self.call("read-monitoring-linked-role", "iam", "get_role", RoleName="AWSServiceRoleForAmazonSSM")
                except ClientError as error:
                    if error.response["Error"]["Code"] != "NoSuchEntity":
                        raise
                else:
                    task = self.call("delete-monitoring-linked-role", "iam", "delete_service_linked_role", RoleName="AWSServiceRoleForAmazonSSM")
                    status = self.wait("monitoring role deletion", lambda: self.client("iam").get_service_linked_role_deletion_status(DeletionTaskId=task["DeletionTaskId"]), lambda r: r["Status"] in ("SUCCEEDED", "FAILED"), 60)
                    assert status["Status"] == "SUCCEEDED", status
                self.expect("absence-monitoring-role", "NoSuchEntity", "iam", "get_role", RoleName="AWSServiceRoleForAmazonSSM")
                proof["monitoring_role"] = True
            except Exception as error:
                errors.append(str(error))
            finally:
                self.stop()
        self.save()
        if errors or not all(proof.values()):
            raise RuntimeError("Alarm cleanup incomplete: " + json.dumps(self.data["alarm_cleanup"]))


if __name__ == "__main__":
    guest.Smoke = AlarmSmoke
    guest.main()
