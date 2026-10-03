#!/usr/bin/env python3
"""Real Resource Groups selection, official-agent execution and SQLite restart.

Reuses the notification smoke's SNS/SQS observation and the firmware-booted guest
workflow. No native AWS endpoints or injected agent results are used.
"""
import json

import ssm_managed_guest_smoke as guest
from ssm_notifications_guest_smoke import NotificationSmoke


class ResourceGroupsSmoke(NotificationSmoke):
    def query(self, value):
        return {"Type": "TAG_FILTERS_1_0", "Query": json.dumps({"ResourceTypeFilters": ["AWS::EC2::Instance"], "TagFilters": [{"Key": "suite", "Values": [value]}]})}

    def group_send(self, label, script, notify=False):
        options = {"InstanceIds": [], "Targets": [{"Key": "resource-groups:Name", "Values": [self.owned["resource_group"]]}, {"Key": "resource-groups:ResourceTypeFilters", "Values": ["AWS::EC2::Instance"]}]}
        if notify:
            options.update(ServiceRoleArn=self.notification_role, NotificationConfig={"NotificationArn": self.owned["notification_topic"], "NotificationType": "Invocation", "NotificationEvents": ["All"]})
        cid = self.send(label, [script], **options)
        if notify:
            self.data["notification_cases"][cid] = {"label": label, "type": "Invocation", "events": ["All"]}
            self.save()
        return cid

    def members(self, expected):
        out = self.call("read-current-group-members", "resource-groups", "list_group_resources", Group=self.owned["resource_group"])
        ids = sorted(row["ResourceArn"].rsplit("/", 1)[-1] for row in out["ResourceIdentifiers"])
        assert ids == expected, (ids, expected)

    def empty(self, cid):
        out = self.wait("excluded-command-completion", lambda: self.client("ssm").list_commands(CommandId=cid), lambda r: r["Commands"][0]["Status"] in guest.TERMINAL)
        command = out["Commands"][0]
        assert command["Status"] == "Success" and command["StatusDetails"] == "NoInstancesInTag" and command["TargetCount"] == 0, command
        assert not self.call("excluded-no-invocations", "ssm", "list_command_invocations", CommandId=cid)["CommandInvocations"]

    def exercise(self):
        self.setup_notifications()
        name = self.prefix + "-members"
        self.call("create-current-owner-group", "resource-groups", "create_group", Name=name, ResourceQuery=self.query(self.prefix))
        self.owned["resource_group"] = name
        self.save()
        self.members([self.owned["instance"]])
        cid = self.group_send("selected-official-agent", "printf actual-resource-group-agent", notify=True)
        result = self.result("selected-official-agent", cid)
        assert result["Status"] == "Success" and result["StandardOutputContent"] == "actual-resource-group-agent", result
        self.await_notifications(cid, ["InProgress", "Success"])
        # The group reads current EC2 tags; no parallel membership catalog exists.
        self.call("exclude-by-current-owner-tag", "ec2", "delete_tags", Resources=[self.owned["instance"]], Tags=[{"Key": "suite"}])
        self.members([])
        excluded = self.group_send("excluded-must-not-execute", "touch /var/tmp/resource-group-exclusion-bug")
        self.empty(excluded)
        check = self.send("verify-excluded-script-never-ran", ["test ! -e /var/tmp/resource-group-exclusion-bug && printf excluded"])
        assert self.result("verify-excluded-script-never-ran", check)["StandardOutputContent"] == "excluded"
        self.call("restore-current-owner-tag", "ec2", "create_tags", Resources=[self.owned["instance"]], Tags=[{"Key": "suite", "Value": self.prefix}])
        self.members([self.owned["instance"]])
        retained = self.group_send("retained-selection", "sleep 8; printf retained-resource-group-selection", notify=True)
        self.call("change-group-after-admission", "resource-groups", "update_group_query", Group=name, ResourceQuery=self.query(self.prefix + "-excluded"))
        self.members([])
        self.stop()
        self.start()
        result = self.result("retained-selection-after-restart", retained, seconds=180)
        assert result["Status"] == "Success" and result["StandardOutputContent"] == "retained-resource-group-selection", result
        self.await_notifications(retained, ["InProgress", "Success"])
        self.empty(self.group_send("changed-query-after-restart", "touch /var/tmp/resource-group-exclusion-bug"))
        self.call("restore-group-query", "resource-groups", "update_group_query", Group=name, ResourceQuery=self.query(self.prefix))
        self.members([self.owned["instance"]])
        cid = self.group_send("current-selection-after-restart", "test ! -e /var/tmp/resource-group-exclusion-bug && printf restored-current-membership")
        assert self.result("current-selection-after-restart", cid)["StandardOutputContent"] == "restored-current-membership"
        self.data["observations"]["resource-group-proof"] = {"selected": self.owned["instance"], "excluded_command": excluded, "retained_command": retained, "official_agent": True, "sqlite_restart": True, "notifications_preserved": True}
        self.save()

    def cleanup(self):
        errors = []
        if self.process is not None and self.owned.get("resource_group"):
            try:
                self.call("delete-owned-resource-group", "resource-groups", "delete_group", Group=self.owned["resource_group"])
                self.expect("absence-resource-group", "NotFoundException", "resource-groups", "get_group", Group=self.owned["resource_group"])
            except Exception as error:
                errors.append(str(error))
        self.data["resource_group_cleanup"] = {"absent": bool(self.owned.get("resource_group")) and not errors, "errors": errors}
        self.save()
        super().cleanup()
        if errors:
            raise RuntimeError("resource group cleanup incomplete: " + json.dumps(errors))


if __name__ == "__main__":
    guest.Smoke = ResourceGroupsSmoke
    guest.main()
