"""CreateBroker replay scenarios for the exact-owned native broker probe."""
import copy
from datetime import datetime, timedelta, timezone
import re
import secrets


def capture_identity(mq, call, success, original, broker_id, broker_arn):
    """Capture replay semantics without requesting a second broker name."""
    def replay(label, changes=None, omitted=()):
        request = copy.deepcopy(original)
        request.update(changes or {})
        for key in omitted:
            request.pop(key, None)
        row = call(mq, "create_broker", request, label)
        if row["code"] == "Success" and row["output"].get("BrokerId") != broker_id:
            raise RuntimeError("Replay returned a different broker for the same unique name")
        return row

    replay("replay-unchanged")
    changed_users = copy.deepcopy(original["Users"])
    changed_users[0]["Password"] = secrets.token_urlsafe(24)
    replay("replay-changed-password", {"Users": changed_users})
    console_users = copy.deepcopy(original["Users"])
    console_users[0]["ConsoleAccess"] = True
    replay("replay-changed-console", {"Users": console_users})
    changed_tags = dict(original["Tags"], mutable="changed")
    replay("replay-changed-tags", {"Tags": changed_tags})
    when = datetime.now(timezone.utc) + timedelta(days=1, hours=2)
    changed_window = {"DayOfWeek": when.strftime("%A").upper(),
                      "TimeOfDay": when.strftime("%H:%M"), "TimeZone": "UTC"}
    replay("replay-changed-window", {"MaintenanceWindowStartTime": changed_window})
    replay("replay-changed-instance", {"HostInstanceType": "mq.m5.large"})
    replay("replay-explicit-default-auth", {"AuthenticationStrategy": "SIMPLE"})
    replay("replay-omitted-token", omitted=("CreatorRequestId",))
    replay("replay-empty-token", {"CreatorRequestId": ""})
    replay("replay-different-token", {"CreatorRequestId": original["CreatorRequestId"] + "-different"})

    success(call(mq, "create_tags", {"ResourceArn": broker_arn, "Tags": changed_tags}, "mutate-tags"))
    success(call(mq, "update_broker", {"BrokerId": broker_id, "MaintenanceWindowStartTime": changed_window}, "mutate-window"))
    success(call(mq, "update_user", {"BrokerId": broker_id, "Username": changed_users[0]["Username"],
                                     "Password": changed_users[0]["Password"]}, "mutate-password"))
    success(call(mq, "describe_broker", {"BrokerId": broker_id}, "after-mutation"))
    replay("replay-original-after-mutation")
    replay("replay-current-values-after-mutation", {"Users": changed_users, "Tags": changed_tags,
                                                    "MaintenanceWindowStartTime": changed_window})


def cleanup_replay_interfaces(mq, ec2, call, success, owned, account):
    """Remove detached replay-created ENIs only after their broker IDs are absent."""
    interfaces = success(call(ec2, "describe_network_interfaces", {
        "Filters": [{"Name": "vpc-id", "Values": [owned["vpc_id"]]}],
    }, "inspect-replay-interfaces", cleanup=True))["NetworkInterfaces"]
    for interface in interfaces:
        if interface["Status"] != "available" or interface.get("Attachment") or interface.get("RequesterManaged"):
            continue
        broker = re.fullmatch(r"Amazon MQ network interface for broker (b-[0-9a-f-]{36})", interface.get("Description", ""))
        if (not broker or interface["OwnerId"] != account
                or interface["VpcId"] != owned["vpc_id"] or interface["SubnetId"] != owned["subnet_id"]
                or {group["GroupId"] for group in interface["Groups"]} != {owned["security_group_id"]}):
            raise RuntimeError("Refusing interface without exact-owned replay provenance")
        row = call(mq, "describe_broker", {"BrokerId": broker[1]}, "verify-replay-interface-broker-absent", cleanup=True)
        if row["code"] != "NotFoundException":
            raise RuntimeError("Refusing interface associated with a present or unverified broker")
        success(call(ec2, "delete_network_interface", {"NetworkInterfaceId": interface["NetworkInterfaceId"]},
                     "delete-owned-orphan-replay-interface", cleanup=True))
