#!/usr/bin/env python3
"""SSM notifications through real official-agent execution, SNS/SQS and SQLite reopen.

Uses the existing managed guest workflow arguments and immutable image/package
inputs; never injects agent status and never connects to native AWS.
"""
import json
import time

import ssm_managed_guest_smoke as guest


class NotificationSmoke(guest.Smoke):
    def setup_notifications(self):
        name = self.prefix + "-notify"
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ssm.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        self.notification_trust = json.dumps(trust)
        self.notification_role = self.call("notification-role", "iam", "create_role", RoleName=name, AssumeRolePolicyDocument=self.notification_trust)["Role"]["Arn"]
        self.owned["notification_role"] = name
        self.owned["notification_topic"] = self.call("notification-topic", "sns", "create_topic", Name=name)["TopicArn"]
        self.owned["notification_queue"] = self.call("notification-queue", "sqs", "create_queue", QueueName=name)["QueueUrl"]
        arn = self.call("notification-queue-arn", "sqs", "get_queue_attributes", QueueUrl=self.owned["notification_queue"], AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage", "Resource": arn, "Condition": {"ArnEquals": {"aws:SourceArn": self.owned["notification_topic"]}}}]}
        self.call("queue-policy", "sqs", "set_queue_attributes", QueueUrl=self.owned["notification_queue"], Attributes={"Policy": json.dumps(policy)})
        self.owned["notification_subscription"] = self.call("notification-subscribe", "sns", "subscribe", TopicArn=self.owned["notification_topic"], Protocol="sqs", Endpoint=arn)["SubscriptionArn"]
        self.role_policy("Allow")
        self.data["notifications"] = []
        self.data["notification_cases"] = {}
        self.save()

    def role_policy(self, effect):
        self.call("publish-role-" + effect, "iam", "put_role_policy", RoleName=self.owned["notification_role"], PolicyName="publish", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": effect, "Action": "sns:Publish", "Resource": self.owned["notification_topic"]}]}))

    def topic_policy(self, effect):
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": effect, "Principal": "*", "Action": "sns:Publish", "Resource": self.owned["notification_topic"]}]}
        self.call("topic-publish-" + effect, "sns", "set_topic_attributes", TopicArn=self.owned["notification_topic"], AttributeName="Policy", AttributeValue=json.dumps(policy))

    def notified_send(self, label, kind, script, events=None, timeout="30"):
        cid = self.send(label, [script], Parameters={"commands": [script], "executionTimeout": [timeout]}, ServiceRoleArn=self.notification_role, NotificationConfig={"NotificationArn": self.owned["notification_topic"], "NotificationType": kind, "NotificationEvents": events or ["All"]})
        self.data["notification_cases"][cid] = {"label": label, "type": kind, "events": events or ["All"]}
        self.save()
        return cid

    def drain_notifications(self, seconds=3):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            out = self.call("notification-receive", "sqs", "receive_message", QueueUrl=self.owned["notification_queue"], MaxNumberOfMessages=10, WaitTimeSeconds=1)
            for message in out.get("Messages", []):
                envelope = json.loads(message["Body"])
                payload = json.loads(envelope["Message"])
                assert envelope["Subject"] == "EC2 Run Command Notification " + guest.REGION, envelope
                case = self.data["notification_cases"][payload["commandId"]]
                assert payload["documentName"] == "AWS-RunShellScript"
                assert payload["status"] in ("InProgress", "Success", "Failed", "Cancelled", "TimedOut")
                assert "All" in case["events"] or payload["status"] in case["events"], (case, payload)
                if case["type"] == "Invocation":
                    assert payload["instanceId"] == self.owned["instance"] and "detailedStatus" in payload
                    assert "instanceIds" not in payload and "expiresAfter" not in payload
                else:
                    assert payload["instanceIds"] == [self.owned["instance"]] and "instanceId" not in payload
                self.data["notifications"].append({"envelope": envelope, "payload": payload})
                self.call("delete-received-notification", "sqs", "delete_message", QueueUrl=self.owned["notification_queue"], ReceiptHandle=message["ReceiptHandle"])
            self.save()

    def statuses(self, cid):
        return {n["payload"]["status"] for n in self.data["notifications"] if n["payload"]["commandId"] == cid}

    def await_notifications(self, cid, expected, seconds=70):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.drain_notifications(2)
            if self.statuses(cid) == set(expected):
                return
        raise AssertionError((cid, self.statuses(cid), expected))

    def exercise(self):
        self.setup_notifications()
        for kind in ("Command", "Invocation"):
            for label, script, timeout, wanted in (("success", "sleep 2; printf 'actual-agent-notification'", "30", "Success"), ("failure", "sleep 2; exit 7", "30", "Failed"), ("execution-timeout", "sleep 20", "5", "TimedOut"), ("cancel", "sleep 60", "90", "Cancelled")):
                cid = self.notified_send(kind + "-" + label, kind, script, timeout=timeout)
                if label == "cancel":
                    self.wait("real-agent-active", lambda: self.client("ssm").list_command_invocations(CommandId=cid), lambda r: r["CommandInvocations"][0]["Status"] == "InProgress", 30)
                    time.sleep(2)
                    self.call("cancel-real-agent-command", "ssm", "cancel_command", CommandId=cid)
                result = self.result(kind + "-" + label, cid)
                assert result["Status"] == wanted, result
                status = "Failed" if kind == "Command" and label == "execution-timeout" else wanted
                self.await_notifications(cid, ["InProgress", status])
            filtered = self.notified_send(kind + "-filtered", kind, "printf filtered-success", events=["Failed"])
            assert self.result(kind + "-filtered", filtered)["Status"] == "Success"
            self.drain_notifications()
            assert not self.statuses(filtered)
        # The command genuinely finishes under denial; the saved transition must
        # survive process shutdown and current-role recovery without agent replay.
        self.role_policy("Deny")
        cid = self.notified_send("role-denied-restart", "Invocation", "printf retained-transition")
        assert self.result("role-denied-restart", cid)["Status"] == "Success"
        self.drain_notifications()
        assert not self.statuses(cid)
        self.stop()
        self.start()
        self.role_policy("Allow")
        self.await_notifications(cid, ["InProgress", "Success"])
        self.topic_policy("Deny")
        cid = self.notified_send("topic-denied", "Command", "printf topic-denied")
        assert self.result("topic-denied", cid)["Status"] == "Success"
        self.drain_notifications()
        assert not self.statuses(cid)
        self.topic_policy("Allow")
        self.await_notifications(cid, ["InProgress", "Success"])
        cid = self.notified_send("trust-denied", "Invocation", "sleep 8; printf trust-recovered", events=["Success"])
        bad = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        self.call("revoke-current-trust", "iam", "update_assume_role_policy", RoleName=self.owned["notification_role"], PolicyDocument=json.dumps(bad))
        assert self.result("trust-denied", cid)["Status"] == "Success"
        self.drain_notifications()
        assert not self.statuses(cid)
        self.call("restore-current-trust", "iam", "update_assume_role_policy", RoleName=self.owned["notification_role"], PolicyDocument=self.notification_trust)
        self.await_notifications(cid, ["Success"])
        # Stop only this owned guest's real agent, with an independent guest timer
        # to resume it. Undelivered work has no fabricated InProgress notification.
        stop = self.send("schedule-agent-offline", ["systemd-run --unit=" + self.prefix + "-resume --timer-property=AccuracySec=100ms --on-active=90 /usr/bin/systemctl start amazon-ssm-agent", "systemd-run --unit=" + self.prefix + "-stop --timer-property=AccuracySec=100ms --on-active=3 /usr/bin/systemctl stop amazon-ssm-agent"])
        assert self.result("schedule-agent-offline", stop)["Status"] == "Success"
        time.sleep(15)
        offline = [self.notified_send("offline-" + kind, kind, "printf must-not-run > /var/tmp/ssm-notification-offline", timeout="5") for kind in ("Command", "Invocation")]
        for cid in offline:
            assert self.result("offline-" + cid, cid, seconds=65)["Status"] == "TimedOut"
            self.await_notifications(cid, ["TimedOut"])
        time.sleep(45)
        recovered = self.send("verify-expired-work-never-executed", ["test ! -e /var/tmp/ssm-notification-offline && printf resumed"], TimeoutSeconds=180)
        assert self.result("verify-expired-work-never-executed", recovered, seconds=180)["Status"] == "Success"
        self.data["observations"]["notification-proof"] = {"cases": len(self.data["notification_cases"]), "sqlite_restart": True, "role_topic_trust_recovery": True, "no_unobserved_inprogress": offline}
        self.save()

    def audit(self):
        # Check the actual published transition against the retained public owner
        # result, including Command/Invocation timeout aggregation differences.
        for cid, case in self.data.get("notification_cases", {}).items():
            command = self.call("audit-notification-command", "ssm", "list_commands", CommandId=cid)["Commands"][0]
            invocation = self.call("audit-notification-invocation", "ssm", "get_command_invocation", CommandId=cid, InstanceId=self.owned["instance"])
            terminal = command["Status"] if case["type"] == "Command" else invocation["Status"]
            assert self.statuses(cid) <= {"InProgress", terminal}, (case, self.statuses(cid), terminal)

    def cleanup(self):
        proof, errors = {}, []
        if self.process is not None:
            for key, service, method, field in (("notification_subscription", "sns", "unsubscribe", "SubscriptionArn"), ("notification_topic", "sns", "delete_topic", "TopicArn"), ("notification_queue", "sqs", "delete_queue", "QueueUrl")):
                if self.owned.get(key):
                    try:
                        self.call("cleanup-" + key, service, method, **{field: self.owned[key]})
                    except Exception as error:
                        errors.append(str(error))
            if self.owned.get("notification_role"):
                for method, extra in (("delete_role_policy", {"PolicyName": "publish"}), ("delete_role", {})):
                    try:
                        self.call("cleanup-" + method, "iam", method, RoleName=self.owned["notification_role"], **extra)
                    except Exception as error:
                        errors.append(str(error))
            for key, service, method, field, code in (("notification_subscription", "sns", "get_subscription_attributes", "SubscriptionArn", "NotFound"), ("notification_topic", "sns", "get_topic_attributes", "TopicArn", "NotFound"), ("notification_queue", "sqs", "get_queue_attributes", "QueueUrl", "AWS.SimpleQueueService.NonExistentQueue"), ("notification_role", "iam", "get_role", "RoleName", "NoSuchEntity")):
                if self.owned.get(key):
                    try:
                        self.expect("absence-" + key, code, service, method, **{field: self.owned[key]})
                        proof[key] = True
                    except Exception as error:
                        errors.append(str(error))
        self.data["notification_cleanup"] = {"absent": proof, "errors": errors}
        self.save()
        super().cleanup()
        if errors:
            raise RuntimeError("notification cleanup incomplete: " + json.dumps(errors))


if __name__ == "__main__":
    guest.Smoke = NotificationSmoke
    guest.main()
