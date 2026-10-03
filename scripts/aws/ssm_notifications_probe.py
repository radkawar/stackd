#!/usr/bin/env python3
"""Bounded native official-agent SNS payload calibration; exact-owned cleanup."""
import argparse
import json
from pathlib import Path
import signal
import time

from ssm_managed_execution_probe import Capture, REGION, CONFIG, interrupt, now


class Notifications(Capture):
    def __init__(self, args):
        super().__init__(args)
        for name in ("sns", "sqs"):
            self.clients[name] = self.session.client(name, config=CONFIG)

    def setup_notifications(self):
        o, p = self.data["owned"], self.data["prefix"] + "-notify"
        self.call("notification-role-absent", "iam", "get_role", {"RoleName": p})
        assert self.data["calls"][-1]["code"] == "NoSuchEntity"
        o["notification_role"] = p
        self.save()
        role = self.call("notification-role", "iam", "create_role", {"RoleName": p, "AssumeRolePolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ssm.amazonaws.com"}, "Action": "sts:AssumeRole"}]})}, required=True)["Role"]["Arn"]
        candidate = "arn:aws:sns:" + REGION + ":" + self.data["account"] + ":" + p
        self.call("notification-topic-absent", "sns", "get_topic_attributes", {"TopicArn": candidate})
        assert self.data["calls"][-1]["code"] == "NotFound"
        o["notification_topic"] = candidate
        self.save()
        o["notification_topic"] = self.call("notification-topic", "sns", "create_topic", {"Name": p}, required=True)["TopicArn"]
        self.save()
        self.call("notification-queue-absent", "sqs", "get_queue_url", {"QueueName": p})
        assert self.data["calls"][-1]["code"] == "AWS.SimpleQueueService.NonExistentQueue"
        o["notification_queue"] = self.call("notification-queue", "sqs", "create_queue", {"QueueName": p}, required=True)["QueueUrl"]
        self.save()
        queue_arn = self.call("notification-queue-arn", "sqs", "get_queue_attributes", {"QueueUrl": o["notification_queue"], "AttributeNames": ["QueueArn"]}, required=True)["Attributes"]["QueueArn"]
        self.call("notification-queue-policy", "sqs", "set_queue_attributes", {"QueueUrl": o["notification_queue"], "Attributes": {"Policy": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage", "Resource": queue_arn, "Condition": {"ArnEquals": {"aws:SourceArn": o["notification_topic"]}}}]})}}, required=True)
        o["notification_subscription"] = self.call("notification-subscribe", "sns", "subscribe", {"TopicArn": o["notification_topic"], "Protocol": "sqs", "Endpoint": queue_arn}, required=True)["SubscriptionArn"]
        self.call("notification-publish-policy", "iam", "put_role_policy", {"RoleName": p, "PolicyName": "publish", "PolicyDocument": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sns:Publish", "Resource": o["notification_topic"]}]})}, required=True)
        self.save()
        return role

    def drain(self, seconds=15):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            result = self.call("notification-receive", "sqs", "receive_message", {"QueueUrl": self.data["owned"]["notification_queue"], "MaxNumberOfMessages": 10, "WaitTimeSeconds": 5}, required=True)
            for message in result.get("Messages", []):
                envelope = json.loads(message["Body"])
                self.data.setdefault("notifications", []).append({"envelope": envelope, "payload": json.loads(envelope["Message"])})
                self.call("notification-delete-message", "sqs", "delete_message", {"QueueUrl": self.data["owned"]["notification_queue"], "ReceiptHandle": message["ReceiptHandle"]}, required=True)
            self.save()

    def exercise(self, iid, role):
        self.wait_ready(iid)
        topic = self.data["owned"]["notification_topic"]
        base = {"DocumentName": "AWS-RunShellScript", "InstanceIds": [iid], "Parameters": {"commands": ["true"]}}
        for label, extras in (
            ("missing-role", {"NotificationConfig": {"NotificationArn": topic, "NotificationEvents": ["All"], "NotificationType": "Command"}}),
            ("role-only", {"ServiceRoleArn": role}),
            ("missing-type", {"ServiceRoleArn": role, "NotificationConfig": {"NotificationArn": topic, "NotificationEvents": ["All"]}}),
            ("missing-events", {"ServiceRoleArn": role, "NotificationConfig": {"NotificationArn": topic, "NotificationType": "Command"}}),
            ("missing-topic", {"ServiceRoleArn": role, "NotificationConfig": {"NotificationType": "Command", "NotificationEvents": ["All"]}}),
        ):
            self.ssm(label, "send_command", {**base, **extras})
        for kind in ("Command", "Invocation"):
            for name, script, timeout, events in (("success", "sleep 2; printf notification-success", "10", ["All"]), ("failed", "sleep 2; exit 7", "10", ["All"]), ("timeout", "sleep 20", "5", ["All"]), ("cancel", "sleep 60", "90", ["All"]), ("filtered", "true", "10", ["Failed"])):
                cid = self.send(kind + "-" + name, iid, [script], ServiceRoleArn=role, Parameters={"commands": [script], "executionTimeout": [timeout]}, NotificationConfig={"NotificationArn": topic, "NotificationEvents": events, "NotificationType": kind})
                if not cid:
                    continue
                if name == "cancel":
                    self.poll("cancel-active", "ssm", "get_command_invocation", {"CommandId": cid, "InstanceId": iid}, lambda r: r.get("Status") == "InProgress", seconds=30, interval=1)
                    self.ssm("cancel", "cancel_command", {"CommandId": cid})
                self.wait_command(kind + "-" + name, cid, iid)
                self.ssm("command-summary", "list_commands", {"CommandId": cid})
                self.drain(8)
        self.drain(20)

    def cleanup(self):
        signal.alarm(0)
        self.cleaning = True
        self.cleanup_deadline = time.monotonic() + 600
        o = self.data["owned"]
        proof = self.data.setdefault("notification_cleanup", {})
        for key, service, method, request in (
            ("notification_subscription", "sns", "unsubscribe", "SubscriptionArn"),
            ("notification_topic", "sns", "delete_topic", "TopicArn"),
            ("notification_queue", "sqs", "delete_queue", "QueueUrl"),
        ):
            if o.get(key):
                self.call("cleanup-" + key, service, method, {request: o[key]})
        if o.get("notification_role"):
            self.call("cleanup-notification-policy", "iam", "delete_role_policy", {"RoleName": o["notification_role"], "PolicyName": "publish"})
            self.call("cleanup-notification-role", "iam", "delete_role", {"RoleName": o["notification_role"]})
        for key, service, method, request, missing in (
            ("notification_subscription", "sns", "get_subscription_attributes", "SubscriptionArn", "NotFound"),
            ("notification_topic", "sns", "get_topic_attributes", "TopicArn", "NotFound"),
            ("notification_queue", "sqs", "get_queue_attributes", "QueueUrl", "AWS.SimpleQueueService.NonExistentQueue"),
            ("notification_role", "iam", "get_role", "RoleName", "NoSuchEntity"),
        ):
            if o.get(key):
                self.call("cleanup-absence-" + key, service, method, {request: o[key]})
                proof[key] = self.data["calls"][-1]["code"] == missing
        self.save()
        super().cleanup()
        if not all(proof.values()):
            raise RuntimeError("Notification cleanup absence not proven")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--live-seconds", type=int, default=2400)
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    args.endpoint = None
    if not 60 <= args.live_seconds <= 2400:
        parser.error("live-seconds must be 60..2400")
    cap = Notifications(args)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
        signal.signal(sig, interrupt)
    try:
        if not args.cleanup_only:
            signal.alarm(args.live_seconds)
            role = cap.setup_notifications()
            cap.exercise(cap.setup_native(), role)
            cap.data["experiment_complete"] = True
            cap.save()
    except Exception as error:
        cap.data["fatal"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        cap.save()
        raise
    finally:
        cap.cleanup()
    print(json.dumps({"evidence": str(args.output), "notifications": len(cap.data.get("notifications", [])), "cleanup": cap.data["cleanup"]["complete"]}))


if __name__ == "__main__":
    main()
