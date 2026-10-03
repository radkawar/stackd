#!/usr/bin/env python3
"""Observe native DynamoDB target-tracking alarm maintenance, never generate load."""
import argparse
import datetime
import json
import os
import pathlib
import secrets
import time

from aws_cli import observe


REGION = "us-east-1"
ROLE = "AWSServiceRoleForApplicationAutoScaling_DynamoDBTable"
SOURCES = [
    "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/AutoScaling.html",
    "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/metrics-dimensions.html",
    "https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_SetAlarmState.html",
    "https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PutScalingPolicy.html",
    "https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Alarms.html",
]


def timestamp(epoch=None):
    return datetime.datetime.fromtimestamp(time.time() if epoch is None else epoch, datetime.timezone.utc).isoformat()


def alarm_key(alarm):
    return (alarm["MetricName"], tuple(sorted((d["Name"], d["Value"]) for d in alarm["Dimensions"])), alarm["ComparisonOperator"])


def compare(before, after):
    previous = {alarm_key(a): a for a in before}
    rows = []
    for alarm in after:
        old = previous.get(alarm_key(alarm))
        if old is None:
            continue
        rows.append({
            "metric": alarm["MetricName"], "dimensions": alarm["Dimensions"],
            "comparison": alarm["ComparisonOperator"], "beforeThreshold": old["Threshold"],
            "afterThreshold": alarm["Threshold"], "thresholdChanged": old["Threshold"] != alarm["Threshold"],
            "alarmNamePreserved": old["AlarmName"] == alarm["AlarmName"],
            "alarmArnPreserved": old["AlarmArn"] == alarm["AlarmArn"],
            "alarmActionsPreserved": old["AlarmActions"] == alarm["AlarmActions"],
            "beforeAlarmName": old["AlarmName"], "afterAlarmName": alarm["AlarmName"],
            "beforeActions": old["AlarmActions"], "afterActions": alarm["AlarmActions"],
        })
    return rows


def findings(capture):
    """Derive summaries only from preserved native rows, without filling missing bins."""
    calls = capture["calls"]
    initial = next((r for r in calls if r["label"] == "initial-alarms" and r.get("code") == "Success"), None)
    result = {"initialAlarmRules": [], "activityObservations": [], "metricObservations": [], "maintenanceHistory": []}
    if initial:
        for alarm in initial["output"].get("MetricAlarms", []):
            spec = next(s for s in capture["experiment"]["specifications"]
                        if sorted(s["dimensions"], key=lambda d: d["Name"]) == sorted(alarm["Dimensions"], key=lambda d: d["Name"])
                        and s["kind"] in alarm["MetricName"])
            rule = {key: alarm[key] for key in ["MetricName", "Dimensions", "Statistic", "Period", "EvaluationPeriods", "ComparisonOperator", "Threshold"]}
            rule.update(callSequence=initial["sequence"], capacity=spec["initialCapacity"], targetValue=70)
            if alarm["MetricName"].startswith("Consumed"):
                rule["observedThresholdCapacityMinuteRatio"] = alarm["Threshold"] / (spec["initialCapacity"] * 60)
            result["initialAlarmRules"].append(rule)
    for row in calls:
        if row.get("code") != "Success":
            continue
        if row["operation"] == "describe-scaling-activities":
            activities = row["output"].get("ScalingActivities", [])
            result["activityObservations"].append({
                "callSequence": row["sequence"], "label": row["label"], "observedAt": row["finishedAt"],
                "includeNotScaledActivities": row["input"]["IncludeNotScaledActivities"],
                "returnedCount": len(activities), "activities": activities,
            })
        if row["operation"] == "get-metric-statistics":
            result["metricObservations"].append({
                "callSequence": row["sequence"], "label": row["label"],
                "period": row["input"]["Period"], "queryStart": row["input"]["StartTime"], "queryEnd": row["input"]["EndTime"],
                "returnedDatapoints": sorted(row["output"].get("Datapoints", []), key=lambda p: p["Timestamp"]),
                "missingBins": "Absent; not synthesized as zero or carried forward.",
            })
        if row["operation"] == "describe-alarm-history" and "-ProvisionedCapacity" in row["input"]["AlarmName"]:
            for event in row["output"].get("AlarmHistoryItems", []):
                if event.get("HistoryItemType") not in ("StateUpdate", "Action", "ConfigurationUpdate"):
                    continue
                result["maintenanceHistory"].append({
                    "callSequence": row["sequence"], "alarmName": row["input"]["AlarmName"],
                    "timestamp": event["Timestamp"], "type": event["HistoryItemType"],
                    "summary": event["HistorySummary"], "data": json.loads(event["HistoryData"]),
                })
    result["interpretationBounds"] = [
        "At target 70 only, observed low utilization ratio is 0.50, consistent with target minus 20 percentage points. Other targets were not measured.",
        "Use snapshot comparisons for observed identity/action preservation; do not infer a refresh from a successful SetAlarmState or PutScalingPolicy response alone.",
        "The table-read manual state transition is synthetic. Untouched table-write and GSI alarm histories are natural controls.",
        "Empty ScalingActivities responses are observations at their timestamps, not a guarantee that maintenance can never create activities.",
        "Explicit policy calls can overlap ongoing native maintenance. Compare alarm creation/deletion history timestamps against each PutScalingPolicy before attributing replacement to that API.",
    ]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path(".stackd/probes/applicationautoscaling/dynamodb_maintenance.json"))
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite native evidence")
    env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_ENDPOINT_URL")}
    env.update(AWS_REGION=REGION, AWS_DEFAULT_REGION=REGION, AWS_MAX_ATTEMPTS="1", AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true")
    table = "stackd-ddb-maint-" + secrets.token_hex(6)
    resource = "table/" + table
    specs = []
    for scope, read, write in [("table", 2, 3), ("index", 4, 5)]:
        for kind, capacity in [("Read", read), ("Write", write)]:
            specs.append({
                "name": scope + kind, "resource": resource + ("/index/by-g" if scope == "index" else ""),
                "dimension": "dynamodb:" + scope + ":" + kind + "CapacityUnits",
                "kind": kind, "initialCapacity": capacity, "updatedCapacity": capacity + 2,
                "dimensions": [{"Name": "TableName", "Value": table}] + ([{"Name": "GlobalSecondaryIndexName", "Value": "by-g"}] if scope == "index" else []),
            })
    capture = {
        "source": "Native AWS DynamoDB, Application Auto Scaling and CloudWatch through aws_cli.observe",
        "startedAt": timestamp(), "region": REGION, "table": table, "sourceReferences": SOURCES,
        "priorEvidence": [".stackd/probes/applicationautoscaling/dynamodb_metrics.json", ".stackd/probes/applicationautoscaling/alarm_signals.json"],
        "experiment": {"targetValue": 70, "disableScaleIn": False, "maxCapacity": 8, "specifications": specs,
                       "naturalObservationSeconds": 1140, "resourceBudgetSeconds": 1500,
                       "syntheticScope": "Only table read ProvisionedCapacityHigh receives SetAlarmState. Other three dimensions are natural controls.",
                       "noDataOperations": True},
        "calls": [], "snapshots": [], "cleanup": {"verifiedAbsent": False},
        "limitations": [
            "Synthetic SetAlarmState delivery is not a naturally evaluated metric transition; history distinguishes them.",
            "A bounded empty scaling-activity response proves only that no activity was returned at that observation, including not-scaled activities.",
            "Absent metric datapoints remain absent, never zero-filled. No traffic or intentional throttling is generated.",
            "One tiny table/GSI with target 70 does not establish formulas for every target, capacity, or AWS timing bound.",
        ],
    }
    attempted_table = False
    targets = []
    policies = []
    initial = []
    history_alarms = {}
    created_at = None

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(capture, indent=2) + "\n")

    def record(label, service, operation, parameters, strict=True):
        row = {"sequence": len(capture["calls"]) + 1, "label": label, "service": service,
               "operation": operation, "region": REGION, "startedAt": timestamp(), "input": parameters}
        capture["calls"].append(row)
        try:
            row.update(observe(service, operation, parameters, env))
        except BaseException as error:
            row["transportError"] = type(error).__name__ + ": " + str(error)
            raise
        finally:
            row["finishedAt"] = timestamp()
            save()
        if strict and row["code"] != "Success":
            raise RuntimeError(label + ": " + row["code"])
        print(json.dumps({"sequence": row["sequence"], "label": label, "code": row["code"]}), flush=True)
        return row

    def key(spec):
        return {"ServiceNamespace": "dynamodb", "ResourceId": spec["resource"], "ScalableDimension": spec["dimension"]}

    def policy(spec):
        return dict(key(spec), PolicyName="maintenance-" + spec["kind"].lower(), PolicyType="TargetTrackingScaling",
                    TargetTrackingScalingPolicyConfiguration={"TargetValue": 70.0, "DisableScaleIn": False,
                        "ScaleInCooldown": 60, "ScaleOutCooldown": 60,
                        "PredefinedMetricSpecification": {"PredefinedMetricType": "DynamoDB" + spec["kind"] + "CapacityUtilization"}})

    def alarms(label):
        return record(label, "cloudwatch", "describe-alarms", {"AlarmNamePrefix": "TargetTracking-" + resource})["output"].get("MetricAlarms", [])

    def active(label):
        deadline = time.monotonic() + 180
        while True:
            row = record(label, "dynamodb", "describe-table", {"TableName": table})
            value = row["output"]["Table"]
            if value["TableStatus"] == "ACTIVE" and all(g["IndexStatus"] == "ACTIVE" for g in value.get("GlobalSecondaryIndexes", [])):
                return value
            if time.monotonic() >= deadline:
                raise RuntimeError("Owned table did not become ACTIVE within 180 seconds")
            time.sleep(3)

    def snapshot(label):
        start = len(capture["calls"]) + 1
        value = alarms(label + "-alarms")
        record(label + "-table", "dynamodb", "describe-table", {"TableName": table})
        for spec in specs:
            record(label + "-policies-" + spec["name"], "application-autoscaling", "describe-scaling-policies", key(spec))
            record(label + "-activities-" + spec["name"], "application-autoscaling", "describe-scaling-activities", dict(key(spec), IncludeNotScaledActivities=True))
        capture["snapshots"].append({"label": label, "firstSequence": start, "lastSequence": len(capture["calls"]), "alarmComparisonToInitial": compare(initial, value)})
        save()
        return value

    def metrics(label):
        end = time.time()
        for spec in specs:
            for period in [60, 300]:
                record(label + "-" + spec["name"] + "-period" + str(period), "cloudwatch", "get-metric-statistics", {
                    "Namespace": "AWS/DynamoDB", "MetricName": "Provisioned" + spec["kind"] + "CapacityUnits",
                    "Dimensions": spec["dimensions"], "StartTime": timestamp(int(created_at // 300) * 300),
                    "EndTime": timestamp(end), "Period": period, "Statistics": ["Average", "Minimum", "Maximum", "Sum", "SampleCount"],
                })

    def histories(label, values):
        for value in values:
            record(label + "-" + value["AlarmName"], "cloudwatch", "describe-alarm-history", {
                "AlarmName": value["AlarmName"], "StartDate": capture["startedAt"], "ScanBy": "TimestampAscending",
            })

    try:
        identity = record("caller-identity", "sts", "get-caller-identity", {})["output"]
        if identity["Account"] != args.account:
            raise RuntimeError("Refusing writes outside approved account")
        capture["account"] = identity["Account"]
        role = record("existing-service-role", "iam", "get-role", {"RoleName": ROLE})["output"]["Role"]
        if role["Arn"] != "arn:aws:iam::" + args.account + ":role/aws-service-role/dynamodb.application-autoscaling.amazonaws.com/" + ROLE:
            raise RuntimeError("Unexpected service-linked role ARN")
        before = record("verify-unique-table-absent", "dynamodb", "describe-table", {"TableName": table}, strict=False)
        if before["code"] != "ResourceNotFoundException":
            raise RuntimeError("Refusing resource name already present or unverifiable")
        attempted_table = True
        created_at = time.time()
        record("create-owned-table", "dynamodb", "create-table", {
            "TableName": table,
            "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "g", "AttributeType": "S"}],
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
            "ProvisionedThroughput": {"ReadCapacityUnits": 2, "WriteCapacityUnits": 3},
            "GlobalSecondaryIndexes": [{"IndexName": "by-g", "KeySchema": [{"AttributeName": "g", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "KEYS_ONLY"}, "ProvisionedThroughput": {"ReadCapacityUnits": 4, "WriteCapacityUnits": 5}}],
        })
        active("initial-active")
        for spec in specs:
            targets.append(spec)
            record("register-" + spec["name"], "application-autoscaling", "register-scalable-target", dict(key(spec), MinCapacity=spec["initialCapacity"], MaxCapacity=8, RoleARN=role["Arn"]))
            policies.append(spec)
            record("initial-policy-" + spec["name"], "application-autoscaling", "put-scaling-policy", policy(spec))
        initial = snapshot("initial")
        if len(initial) != 16:
            raise RuntimeError("Expected four complete alarm families before capacity update")
        metrics("initial-metrics")
        record("explicit-capacity-update", "dynamodb", "update-table", {
            "TableName": table, "ProvisionedThroughput": {"ReadCapacityUnits": 4, "WriteCapacityUnits": 5},
            "GlobalSecondaryIndexUpdates": [{"Update": {"IndexName": "by-g", "ProvisionedThroughput": {"ReadCapacityUnits": 6, "WriteCapacityUnits": 7}}}],
        })
        active("updated-active")
        updated_at = time.time()
        capture["capacityUpdateActiveAt"] = timestamp(updated_at)
        snapshot("after-capacity-update-before-synthetic")
        chosen = next(a for a in initial if "-ProvisionedCapacityHigh-" in a["AlarmName"] and a["MetricName"] == "ProvisionedReadCapacityUnits" and len(a["Dimensions"]) == 1)
        record("synthetic-maintenance-reset", "cloudwatch", "set-alarm-state", {"AlarmName": chosen["AlarmName"], "StateValue": "OK", "StateReason": "Owned maintenance probe reset before synthetic action delivery"})
        now = datetime.datetime.now(datetime.timezone.utc)
        native_time = lambda value: value.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"
        reason = {"version": "1.0", "queryDate": native_time(now), "startDate": native_time(now - datetime.timedelta(seconds=900)),
                  "statistic": "Average", "period": 300, "recentDatapoints": [4.0, 4.0, 4.0], "threshold": chosen["Threshold"],
                  "evaluatedDatapoints": [{"timestamp": native_time(now - datetime.timedelta(seconds=300 * n)), "sampleCount": 1.0, "value": 4.0} for n in [1, 2, 3]]}
        record("synthetic-maintenance-alarm", "cloudwatch", "set-alarm-state", {"AlarmName": chosen["AlarmName"], "StateValue": "ALARM",
               "StateReason": "Synthetic owned maintenance probe: current real capacity is 4; datapoints are synthetic, not CloudWatch publication evidence",
               "StateReasonData": json.dumps(reason)})
        time.sleep(20)
        synthetic = snapshot("after-synthetic-delivery")
        histories("synthetic-history", [chosen])
        capture["syntheticThresholdRefreshObserved"] = any(r["thresholdChanged"] and len(r["dimensions"]) == 1 and "Read" in r["metric"] for r in compare(initial, synthetic))
        deadline = min(updated_at + 1140, created_at + 1320)
        attempt = 0
        while time.time() < deadline:
            time.sleep(min(60, max(0, deadline - time.time())))
            current = alarms("natural-watch-" + str(attempt))
            # Untouched table-write and GSI alarms are controls for natural maintenance.
            controls = [r for r in compare(initial, current) if "Provisioned" in r["metric"] and not (len(r["dimensions"]) == 1 and "Read" in r["metric"])]
            if len(controls) == 6 and all(r["thresholdChanged"] for r in controls):
                capture["naturalWatchStopReason"] = "All six untouched provisioned maintenance alarm thresholds changed; examine histories for actual metric-driven transitions."
                break
            attempt += 1
        else:
            capture["naturalWatchStopReason"] = "Bounded 19-minute post-update observation completed without all untouched maintenance thresholds changing."
        natural = snapshot("after-natural-observation")
        capture["naturalObservationEndedAt"] = timestamp()
        metrics("after-natural-metrics")
        history_alarms = {a["AlarmName"]: a for a in initial + synthetic + natural}
        histories("before-explicit-refresh-history", list(history_alarms.values()))
        # Idle scale-in can undo the first manual increase before three provisioned
        # periods arrive. Reapply it so explicit refresh observes current capacity.
        current_table = active("explicit-refresh-control-before-update")
        capacity_update = {"TableName": table}
        table_capacity = {"ReadCapacityUnits": 4, "WriteCapacityUnits": 5}
        index_capacity = {"ReadCapacityUnits": 6, "WriteCapacityUnits": 7}
        if any(current_table["ProvisionedThroughput"][k] != v for k, v in table_capacity.items()):
            capacity_update["ProvisionedThroughput"] = table_capacity
        current_index = next(g for g in current_table["GlobalSecondaryIndexes"] if g["IndexName"] == "by-g")
        if any(current_index["ProvisionedThroughput"][k] != v for k, v in index_capacity.items()):
            capacity_update["GlobalSecondaryIndexUpdates"] = [{"Update": {"IndexName": "by-g", "ProvisionedThroughput": index_capacity}}]
        if len(capacity_update) > 1:
            record("explicit-refresh-control-capacity-update", "dynamodb", "update-table", capacity_update)
            active("explicit-refresh-control-active")
        before_refresh = alarms("explicit-refresh-control-alarms-before-policy")
        for spec in specs:
            record("explicit-policy-refresh-" + spec["name"], "application-autoscaling", "put-scaling-policy", policy(spec))
        time.sleep(15)
        refreshed = snapshot("after-explicit-policy-refresh")
        capture["explicitRefreshComparison"] = compare(before_refresh, refreshed)
        history_alarms.update({a["AlarmName"]: a for a in before_refresh + refreshed})
        capture["workflowComplete"] = True
    except BaseException as error:
        capture["workflowError"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        errors = []
        for spec in policies:
            try:
                row = record("cleanup-policy-" + spec["name"], "application-autoscaling", "delete-scaling-policy", dict(key(spec), PolicyName=policy(spec)["PolicyName"]), strict=False)
                if row["code"] not in ("Success", "ObjectNotFoundException"):
                    errors.append(row["label"] + ": " + row["code"])
            except BaseException as error:
                errors.append(str(error))
        for spec in targets:
            try:
                row = record("cleanup-target-" + spec["name"], "application-autoscaling", "deregister-scalable-target", key(spec), strict=False)
                if row["code"] not in ("Success", "ObjectNotFoundException"):
                    errors.append(row["label"] + ": " + row["code"])
            except BaseException as error:
                errors.append(str(error))
        table_absent = not attempted_table
        if attempted_table:
            try:
                row = record("cleanup-delete-table", "dynamodb", "delete-table", {"TableName": table}, strict=False)
                if row["code"] not in ("Success", "ResourceNotFoundException"):
                    errors.append(row["label"] + ": " + row["code"])
                for attempt in range(45):
                    row = record("cleanup-verify-table-" + str(attempt), "dynamodb", "describe-table", {"TableName": table}, strict=False)
                    if row["code"] == "ResourceNotFoundException":
                        table_absent = True
                        break
                    time.sleep(2)
            except BaseException as error:
                errors.append(str(error))
        scaling_absent = True
        if targets:
            try:
                for rid in [resource, resource + "/index/by-g"]:
                    for operation, result_field in [("describe-scalable-targets", "ScalableTargets"), ("describe-scaling-policies", "ScalingPolicies")]:
                        params = {"ServiceNamespace": "dynamodb", "ResourceIds": [rid]} if operation == "describe-scalable-targets" else {"ServiceNamespace": "dynamodb", "ResourceId": rid}
                        row = record("cleanup-verify-" + operation + "-" + rid, "application-autoscaling", operation, params)
                        scaling_absent = scaling_absent and not row["output"].get(result_field)
                remaining = alarms("cleanup-verify-alarms")
                scaling_absent = scaling_absent and not remaining
            except BaseException as error:
                errors.append(str(error))
                scaling_absent = False
        capture["cleanup"].update(verifiedAbsent=table_absent and scaling_absent and not errors, errors=errors,
                                  roleUntouched=True, tableAbsent=table_absent, scalingResourcesAbsent=scaling_absent)
        capture["finishedAt"] = timestamp()
        if created_at is not None:
            capture["resourceLifetimeSeconds"] = time.time() - created_at
        try:
            if capture.get("workflowComplete"):
                histories("after-cleanup-final-history", list(history_alarms.values()))
        except BaseException as error:
            capture["finalHistoryError"] = type(error).__name__ + ": " + str(error)
            raise
        finally:
            capture["findings"] = findings(capture)
            save()
        if not capture["cleanup"]["verifiedAbsent"]:
            raise RuntimeError("Owned resource cleanup not verified: " + json.dumps(capture["cleanup"]))


if __name__ == "__main__":
    main()
