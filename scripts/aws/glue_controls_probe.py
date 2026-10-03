#!/usr/bin/env python3
"""Bounded Glue metadata controls: classifiers/connections/crawlers/workflows/jobs.

Never calls StartCrawler, StartWorkflowRun or StartJobRun. The ON_DEMAND trigger
points only at an owned-name nonexistent job; it may create workflow-run metadata,
but cannot execute an existing paid job. No catalog encryption/defaults are changed.
"""
import json
import uuid

from glue_native_common import Capture, arguments, require

REFERENCES = ["https://docs.aws.amazon.com/glue/latest/webapi/API_" + name + ".html" for name in (
    "CreateClassifier", "UpdateClassifier", "CreateConnection", "GetConnection",
    "GetDataCatalogEncryptionSettings", "CreateCrawler", "UpdateCrawler", "CreateWorkflow",
    "GetWorkflowRunProperties", "CreateTrigger", "StartTrigger", "StopTrigger",
    "CreateSecurityConfiguration", "TagResource", "GetTags", "CreateJob", "UpdateJob")]


def main():
    cap = Capture(arguments(__doc__, member_account=True), "stackd-controls-", REFERENCES, {
        "max_calls": 110, "wall_seconds": 480, "cli_timeout_seconds": 30,
        "max_classifiers": 2, "max_connections": 1, "max_crawlers": 1, "max_empty_buckets": 1,
        "max_workflows": 1, "max_triggers": 1, "max_security_configurations": 2,
        "max_iam_roles": 1, "max_jobs": 1, "max_databases": 1, "max_job_runs": 0, "max_crawler_runs": 0,
        "cost_usd_upper_estimate": 0.01, "cost_basis": "Metadata APIs only, zero compute; no standing global resource listings.",
    })
    name = cap.prefix
    database = cap.name(name.replace("-", "_"), "stackd_controls_owned")
    owned = {"role": False, "classifiers": [], "connection": False, "crawler": False,
             "workflow": False, "trigger": False, "security": [], "job": False, "database": False, "bucket": False}
    def call(label, operation, parameters):
        return cap.request(label, "glue", operation, parameters)
    try:
        cap.identity()
        cap.capture["uncertainty"] = [
            "No crawler classification, JDBC connectivity, successful workflow data-plane execution or KMS-protected password retrieval proved. StartTrigger with a missing job may create workflow-run metadata.",
            "All PASSWORD/ENCRYPTED_PASSWORD values are redacted before persistence, including synthetic inputs; presence and HidePassword removal retained.",
            "GetDataCatalogEncryptionSettings is a single read of this account's default configuration, not a standing-resource scan or mutation.",
        ]
        role_name = name + "-role"
        owned["role"] = True
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        role = require(cap.request("create-owned-role", "iam", "create-role", {"RoleName": role_name, "AssumeRolePolicyDocument": json.dumps(trust)}))["Role"]
        cap.name(role["RoleId"], "CONTROLS_ROLE_ID")
        owned["bucket"] = True
        require(cap.request("create-empty-crawler-bucket", "s3api", "create-bucket", {"Bucket": name}))
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"], "Resource": f"arn:aws:s3:::{name}"}]}
        require(cap.request("owned-crawler-policy", "iam", "put-role-policy", {"RoleName": role_name, "PolicyName": "owned", "PolicyDocument": json.dumps(policy)}))
        for kind in ("Csv", "Json"):
            classifier = name + "-" + kind.lower()
            owned["classifiers"].append(classifier)
            definition = {"Name": classifier, "Delimiter": ",", "QuoteSymbol": '"', "ContainsHeader": "PRESENT", "Header": ["category", "amount"]} if kind == "Csv" else {"Name": classifier, "JsonPath": "$[*]"}
            require(call("create-" + kind + "-classifier", "create-classifier", {kind + "Classifier": definition}))
            call("duplicate-" + kind + "-classifier", "create-classifier", {kind + "Classifier": definition})
            call("get-" + kind + "-classifier", "get-classifier", {"Name": classifier})
            update = {"Name": classifier, "Delimiter": "|"} if kind == "Csv" else {"Name": classifier, "JsonPath": "$.items[*]"}
            call("update-" + kind + "-classifier", "update-classifier", {kind + "Classifier": update})
            call("get-updated-" + kind + "-classifier", "get-classifier", {"Name": classifier})
        call("catalog-encryption-settings", "get-data-catalog-encryption-settings", {"CatalogId": cap.account})
        password = uuid.uuid4().hex
        cap.name(password, "SYNTHETIC_PASSWORD_REDACTED")
        connection = {"Name": name, "ConnectionType": "JDBC", "Description": "first", "ConnectionProperties": {"JDBC_CONNECTION_URL": "jdbc:postgresql://127.0.0.1:5432/owned", "USERNAME": "owned", "PASSWORD": password}}
        owned["connection"] = True
        require(call("create-connection", "create-connection", {"ConnectionInput": connection}))
        call("duplicate-connection", "create-connection", {"ConnectionInput": connection})
        call("get-connection-default", "get-connection", {"Name": name})
        call("get-connection-visible", "get-connection", {"Name": name, "HidePassword": False})
        call("get-connection-hidden", "get-connection", {"Name": name, "HidePassword": True})
        call("get-connection-other-catalog", "get-connection", {"Name": name, "CatalogId": cap.args.member_account, "HidePassword": True})
        call("update-connection", "update-connection", {"Name": name, "ConnectionInput": dict(connection, Description="second")})
        call("get-connection-after-update", "get-connection", {"Name": name, "HidePassword": True})
        owned["database"] = True
        require(call("create-crawler-database", "create-database", {"DatabaseInput": {"Name": database}}))
        owned["crawler"] = True
        crawler = {"Name": name, "Role": role["Arn"], "DatabaseName": database, "Targets": {"S3Targets": [{"Path": f"s3://{name}/never-scanned/"}]}, "Classifiers": [name + "-csv"]}
        call("create-crawler-invalid-targets", "create-crawler", dict(crawler, Targets={}))
        require(call("create-crawler", "create-crawler", crawler))
        call("duplicate-crawler", "create-crawler", crawler)
        call("get-crawler", "get-crawler", {"Name": name})
        call("update-crawler", "update-crawler", {"Name": name, "Description": "updated", "RecrawlPolicy": {"RecrawlBehavior": "CRAWL_NEW_FOLDERS_ONLY"}})
        call("get-updated-crawler", "get-crawler", {"Name": name})
        call("stop-ready-crawler", "stop-crawler", {"Name": name})
        owned["workflow"] = True
        workflow = {"Name": name, "DefaultRunProperties": {"first": "one", "retained": "yes"}, "MaxConcurrentRuns": 1, "Tags": {"owned": "yes"}}
        require(call("create-workflow", "create-workflow", workflow))
        call("duplicate-workflow", "create-workflow", workflow)
        call("get-workflow", "get-workflow", {"Name": name, "IncludeGraph": True})
        call("update-workflow", "update-workflow", {"Name": name, "DefaultRunProperties": {"second": "two"}})
        call("get-updated-workflow", "get-workflow", {"Name": name, "IncludeGraph": True})
        call("get-missing-workflow-run-properties", "get-workflow-run-properties", {"Name": name, "RunId": "wr_" + "0" * 64})
        trigger = {"Name": name, "Type": "ON_DEMAND", "Actions": [{"JobName": name + "-nonexistent"}], "WorkflowName": name}
        owned["trigger"] = True
        call("create-on-demand-start-on-creation", "create-trigger", dict(trigger, StartOnCreation=True))
        require(call("create-on-demand-trigger", "create-trigger", trigger))
        call("get-trigger", "get-trigger", {"Name": name})
        call("start-trigger-missing-job", "start-trigger", {"Name": name})
        call("get-trigger-after-start", "get-trigger", {"Name": name})
        call("stop-on-demand-trigger", "stop-trigger", {"Name": name})
        call("get-trigger-after-stop", "get-trigger", {"Name": name})
        security = {"S3Encryption": [{"S3EncryptionMode": "SSE-S3"}], "CloudWatchEncryption": {"CloudWatchEncryptionMode": "DISABLED"}, "JobBookmarksEncryption": {"JobBookmarksEncryptionMode": "DISABLED"}}
        owned["security"].append(name)
        require(call("create-security", "create-security-configuration", {"Name": name, "EncryptionConfiguration": security}))
        call("duplicate-security", "create-security-configuration", {"Name": name, "EncryptionConfiguration": security})
        call("get-security", "get-security-configuration", {"Name": name})
        owned["security"].append(name + "-invalid")
        call("create-security-missing-kms-key", "create-security-configuration", {"Name": name + "-invalid", "EncryptionConfiguration": {"JobBookmarksEncryption": {"JobBookmarksEncryptionMode": "CSE-KMS"}}})
        arn = f"arn:aws:glue:us-east-1:{cap.account}:workflow/{name}"
        call("get-workflow-tags", "get-tags", {"ResourceArn": arn})
        call("merge-workflow-tags", "tag-resource", {"ResourceArn": arn, "TagsToAdd": {"added": "two", "owned": "updated"}})
        call("get-merged-workflow-tags", "get-tags", {"ResourceArn": arn})
        call("remove-workflow-tags", "untag-resource", {"ResourceArn": arn, "TagsToRemove": ["owned", "missing"]})
        call("get-remaining-workflow-tags", "get-tags", {"ResourceArn": arn})
        call("get-tags-malformed-arn", "get-tags", {"ResourceArn": "not-an-arn"})
        call("get-tags-missing-resource", "get-tags", {"ResourceArn": arn + "-missing"})
        call("get-tags-other-region", "get-tags", {"ResourceArn": arn.replace("us-east-1", "us-west-2")})
        owned["job"] = True
        job = {"Name": name, "Role": role["Arn"], "Command": {"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": f"s3://{name}/not-executed.py"}, "Description": "first", "DefaultArguments": {"--owned": "initial"}, "MaxCapacity": 0.0625, "MaxRetries": 0, "Timeout": 1}
        require(call("create-job-no-run", "create-job", job))
        call("create-job-exact-duplicate", "create-job", job)
        call("create-job-changed-description", "create-job", dict(job, Description="second"))
        call("get-job-after-duplicate", "get-job", {"JobName": name})
        call("create-job-changed-script", "create-job", dict(job, Command=dict(job["Command"], ScriptLocation=f"s3://{name}/different.py")))
        call("update-job-omitted-fields", "update-job", {"JobName": name, "JobUpdate": {"Role": role["Arn"], "Command": job["Command"], "MaxCapacity": 0.0625, "MaxRetries": 0, "Timeout": 1}})
        call("get-job-after-replacement", "get-job", {"JobName": name})
        cap.capture["completed"] = True
    except Exception as error:
        cap.capture["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        cap.cleaning = True
        remaining = []
        items = [("job", "delete-job", "get-job", {"JobName": name}), ("trigger", "delete-trigger", "get-trigger", {"Name": name}), ("workflow", "delete-workflow", "get-workflow", {"Name": name}), ("crawler", "delete-crawler", "get-crawler", {"Name": name}), ("connection", "delete-connection", "get-connection", {"Name": name}), ("database", "delete-database", "get-database", {"Name": database})]
        for kind, delete, get, parameters in items:
            if owned[kind]:
                call("cleanup-" + kind, delete, {"ConnectionName": name} if kind == "connection" else parameters)
                if call("verify-" + kind + "-absent", get, parameters)["code"] != "EntityNotFoundException":
                    remaining.append(kind + ":" + name)
        for classifier in owned["classifiers"]:
            call("cleanup-classifier", "delete-classifier", {"Name": classifier})
            if call("verify-classifier-absent", "get-classifier", {"Name": classifier})["code"] != "EntityNotFoundException":
                remaining.append(classifier)
        for security_name in owned["security"]:
            call("cleanup-security", "delete-security-configuration", {"Name": security_name})
            if call("verify-security-absent", "get-security-configuration", {"Name": security_name})["code"] != "EntityNotFoundException":
                remaining.append(security_name)
        if owned["bucket"]:
            cap.request("cleanup-empty-bucket", "s3api", "delete-bucket", {"Bucket": name})
            if cap.request("verify-empty-bucket-absent", "s3api", "head-bucket", {"Bucket": name})["code"] not in ("404", "NoSuchBucket", "NotFound"):
                remaining.append(name)
        if owned["role"]:
            cap.request("cleanup-owned-policy", "iam", "delete-role-policy", {"RoleName": role_name, "PolicyName": "owned"})
            cap.request("cleanup-role", "iam", "delete-role", {"RoleName": role_name})
            if cap.request("verify-role-absent", "iam", "get-role", {"RoleName": role_name})["code"] != "NoSuchEntity":
                remaining.append(role_name)
        cap.finish(remaining)


if __name__ == "__main__":
    main()
