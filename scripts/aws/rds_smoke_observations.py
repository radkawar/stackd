"""CloudTrail/S3, EventBridge/SQS and measured CloudWatch RDS smoke assertions."""
import datetime
import json
import urllib.request

from cloudtrail_events import collect_s3


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def advance(app, duration):
    request = urllib.request.Request(app.endpoint + "/_stackd/clock", data=json.dumps({"advance": duration}).encode(),
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        instant = json.load(response)["time"]
    request = urllib.request.Request(app.endpoint + "/_stackd/jobs/drain?limit=1000", data=b"")
    with urllib.request.urlopen(request, timeout=180) as response:
        require("error" not in json.load(response), "job drain failed")
    return instant


def setup(app):
    s3, trail, sqs, events = [app.client(s) for s in ("s3", "cloudtrail", "sqs", "events")]
    app.bucket, app.trail = app.prefix + "-audit", app.prefix + "-trail"
    trail_arn = f"arn:aws:cloudtrail:us-east-1:000000000000:trail/{app.trail}"
    s3.create_bucket(Bucket=app.bucket)
    policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "s3:GetBucketAcl",
         "Resource": "arn:aws:s3:::" + app.bucket, "Condition": {"StringEquals": {"aws:SourceArn": trail_arn}}},
        {"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}, "Action": "s3:PutObject",
         "Resource": "arn:aws:s3:::" + app.bucket + "/AWSLogs/000000000000/*",
         "Condition": {"StringEquals": {"aws:SourceArn": trail_arn, "s3:x-amz-acl": "bucket-owner-full-control"}}}]}
    s3.put_bucket_policy(Bucket=app.bucket, Policy=json.dumps(policy))
    trail.create_trail(Name=app.trail, S3BucketName=app.bucket)
    trail.put_event_selectors(TrailName=app.trail, AdvancedEventSelectors=[
        {"Name": "RDSData", "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]},
            {"Field": "resources.type", "Equals": ["AWS::RDS::DBCluster"]}]},
        {"Name": "Management", "FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}]}])
    trail.start_logging(Name=app.trail)
    app.queue = sqs.create_queue(QueueName=app.prefix + "-events")["QueueUrl"]
    queue_arn = sqs.get_queue_attributes(QueueUrl=app.queue, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    app.rule = app.prefix + "-events"
    rule_arn = events.put_rule(Name=app.rule, EventPattern=json.dumps({
        "source": ["aws.rds"],
        "detail-type": ["RDS DB Instance Event", "RDS DB Cluster Event",
                        "RDS DB Snapshot Event", "RDS DB Cluster Snapshot Event"]}))["RuleArn"]
    sqs.set_queue_attributes(QueueUrl=app.queue, Attributes={"Policy": json.dumps({"Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"}, "Action": "sqs:SendMessage",
                       "Resource": queue_arn, "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}}}]})})
    require(events.put_targets(Rule=app.rule, Targets=[{"Id": "queue", "Arn": queue_arn}])["FailedEntryCount"] == 0,
            "RDS event target rejected")


def verify(app, cluster, secret):
    arn = cluster["DBClusterArn"]
    tx = app.data.begin_transaction(resourceArn=arn, secretArn=secret, database="appdb")["transactionId"]
    now = advance(app, "1m")
    app.data.rollback_transaction(resourceArn=arn, secretArn=secret, transactionId=tx)
    timestamp = datetime.datetime.fromisoformat(now.replace("Z", "+00:00"))
    points = app.client("cloudwatch").get_metric_statistics(Namespace="AWS/RDS", MetricName="DatabaseConnections",
        Dimensions=[{"Name": "DBInstanceIdentifier", "Value": cluster["DBClusterIdentifier"] + "-writer"}],
        StartTime=timestamp-datetime.timedelta(minutes=2), EndTime=timestamp+datetime.timedelta(minutes=1),
        Period=60, Statistics=["Maximum"])["Datapoints"]
    require(any(point["Maximum"] >= 1 for point in points), "held native transaction missing from measured connections")
    advance(app, "6m")
    s3 = app.client("s3")
    capture = collect_s3(
        lambda p: s3.list_objects_v2(**p), lambda p: s3.get_object(**p), {},
        bucket=app.bucket, related=lambda event: True)
    require(not capture["partial"], "owned trail collection was incomplete")
    records = [row["event"] for row in capture["events"]]
    calls = [record for record in records if record["eventSource"] == "rdsdataapi.amazonaws.com"]
    names = {record["eventName"] for record in calls}
    require({"ExecuteStatement", "BatchExecuteStatement", "BeginTransaction", "CommitTransaction", "RollbackTransaction"} <= names,
            "actual trail delivery omitted Data API operations")
    require(all(record["eventType"] == "Rds Data Service" and record["eventCategory"] == "Data" for record in calls),
            "Data API event type/category did not survive persistence and delivery")
    require(any(record["eventSource"] == "rds.amazonaws.com" and record["eventType"] == "AwsApiCall" for record in records),
            "default management event type changed")
    require(app.password not in json.dumps(records) and "123456789012.3456" not in json.dumps(calls),
            "data-plane credential or bound value leaked into audit")
    require(all((record.get("requestParameters") or {}).get("sql", "**********") == "**********" for record in calls),
            "SQL text leaked into audit")
    delivered = app.client("sqs").receive_message(QueueUrl=app.queue, MaxNumberOfMessages=10).get("Messages", [])
    event_ids = {json.loads(item["Body"])["detail"]["EventID"] for item in delivered}
    require("RDS-EVENT-0005" in event_ids, "actual RDS creation event did not reach SQS")
    app.report["observations"]["audit"] = {"data_operations": sorted(names), "event_type": "Rds Data Service",
        "delivered_data_records": len(calls), "persisted_before_restart": True, "sql_and_values_redacted": True}
    app.report["observations"]["events"] = sorted(event_ids)
    app.report["observations"]["metrics"] = {"held_connection_measured": True}


def cleanup(app):
    if app.rule:
        events = app.client("events")
        events.remove_targets(Rule=app.rule, Ids=["queue"])
        events.delete_rule(Name=app.rule)
    if app.queue:
        app.client("sqs").delete_queue(QueueUrl=app.queue)
    if app.trail:
        trail = app.client("cloudtrail")
        trail.stop_logging(Name=app.trail)
        trail.delete_trail(Name=app.trail)
    if app.bucket:
        s3 = app.client("s3")
        for item in s3.list_objects_v2(Bucket=app.bucket).get("Contents", []):
            s3.delete_object(Bucket=app.bucket, Key=item["Key"])
        s3.delete_bucket(Bucket=app.bucket)
