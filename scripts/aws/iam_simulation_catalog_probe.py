#!/usr/bin/env python3
"""Capture all generated IAM actions' simulator resource presentation metadata.

Only SimulateCustomPolicy and a read-only credential check are called. All
resources and policies supplied to the simulator are hypothetical. No AWS
resource is created. Run --capture --resume to extend an atomic checkpoint.
Ordinary tests consume the checked-in fixture without network access.
"""

import argparse
import concurrent.futures
import gzip
import json
from pathlib import Path
import re
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True
from iam_simulation_probe import ALLOW_ALL, call, policy, stamp, statement


ROOT = Path(__file__).resolve().parents[2]
CATALOGUE = ROOT / "internal/iam/catalog/data/catalog.json.gz"
DESTINATION = ROOT / '.stackd/probes/iam/simulation_catalog.json'
ANCHOR = "iam:GetUser"
COMMON = {"PolicyInputList": [ALLOW_ALL],
          "ResourceArns": ["arn:aws:s3:::stackd-simulation/a", "arn:aws:s3:::stackd-simulation/b"],
          "MaxItems": 1000}
TRANSIENT = {"Throttling", "ThrottlingException", "RequestLimitExceeded", "ServiceFailure", "ServiceUnavailable", "InternalFailure", "CLITimeout"}


def catalogue():
    compressed = CATALOGUE.read_bytes()
    decompressed = gzip.decompress(compressed)
    data = json.loads(decompressed)
    names = [action["name"] for service in data["services"] for action in service["actions"]]
    if len(names) != len(set(names)):
        raise RuntimeError("Generated catalogue contains duplicate exact action spellings")
    source = {"path": str(CATALOGUE.relative_to(ROOT)),
              "revision": data["source"]["revision"], "repository": data["source"]["repository"],
              "service_count": len(data["services"]), "action_count": len(names)}
    return names, source


class Capture:
    def __init__(self, resume):
        self.names, source = catalogue()
        self.positions = {name: index for index, name in enumerate(self.names)}
        self.lock = threading.RLock()
        self.limiter = threading.Lock()
        self.next_call = 0.0
        self.last_checkpoint = 0.0
        self.account = ""
        self.caller_arn = ""
        if resume and DESTINATION.exists():
            self.fixture = json.loads(DESTINATION.read_text())
            if self.fixture["catalogue"] != source or self.fixture["request_common"] != COMMON:
                raise RuntimeError("Checkpoint source/profile differs from the current catalogue")
        else:
            self.fixture = {"schema_version": 1, "operation": "SimulateCustomPolicy",
                            "endpoint": "https://iam.amazonaws.com", "region": "us-east-1",
                            "started_at": stamp(), "probe": "scripts/aws/iam_simulation_catalog_probe.py",
                            "catalogue": source, "request_common": COMMON, "actions": [], "requests": [],
                            "representative_responses": [], "failures": [], "capture_complete": False,
                            "no_resource_writes": True, "cleanup_verified": True}
        self.completed = {row["action"]: row for row in self.fixture["actions"]}
        self.fixture["profile_complete"] = {
            "multiple": len(self.completed) == len(self.names),
            "default": all(name in self.completed and "default_result" in self.completed[name] for name in self.names),
            "single": all(name in self.completed and "single_result" in self.completed[name] for name in self.names),
        }
        self.fixture["capture_complete"] = all(self.fixture["profile_complete"].values())
        self.counter = max((int(row["id"][1:]) for row in self.fixture["requests"]), default=0)
        self.fixture["documentation"] = ["https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulateCustomPolicy.html",
                                           "https://docs.aws.amazon.com/IAM/latest/APIReference/API_EvaluationResult.html"]
        self.fixture["provenance"] = "Request inputs are request_common plus each requests.actions unless requests.input is present. Full representative responses retain API field presence. Source path and revision identify the generated action catalogue. No raw HTTP debug logs, credentials, actual account resources or account policies are persisted."
        self.fixture["classification"] = "resource_aware means compatible with the independently tested iam:GetUser anchor in an otherwise identical explicit-resource request. False requires a successful homogeneous request plus an InvalidInput response proving adding that anchor mixes authorization-information groups. This is simulator grouping, not an assertion that an action exists or does not exist in AWS."

    def sanitize(self, value):
        if isinstance(value, dict):
            return {key: self.sanitize(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.sanitize(item) for item in value]
        if isinstance(value, str):
            if self.caller_arn:
                value = value.replace(self.caller_arn, "arn:aws:iam::123456789012:user/stackd-catalogue-probe")
            if self.account:
                value = value.replace(self.account, "123456789012")
        return value

    def checkpoint(self, force=False):
        with self.lock:
            if not force and time.monotonic() - self.last_checkpoint < 5:
                return
            self.fixture["actions"] = [self.completed[name] for name in self.names if name in self.completed]
            self.fixture["finished_at"] = stamp()
            self.fixture["captured_action_count"] = len(self.completed)
            temporary = DESTINATION.with_suffix(".json.tmp")
            temporary.write_text(json.dumps(self.fixture, indent=2) + "\n")
            temporary.replace(DESTINATION)
            self.last_checkpoint = time.monotonic()
            modes = {name: sum(name + "_result" in row for row in self.completed.values()) for name in ("default", "single")}
            print("checkpoint", len(self.completed), "/", len(self.names), "actions;", modes, ";", len(self.fixture["requests"]), "requests", flush=True)

    def throttle(self):
        with self.limiter:
            delay = max(0.0, self.next_call - time.monotonic())
            if delay:
                time.sleep(delay)
            self.next_call = time.monotonic() + 0.2

    def request(self, names, parent=None, inputs=None, purpose="catalogue", profile=None):
        parameters = inputs if inputs is not None else {**COMMON, "ActionNames": names}
        with self.lock:
            self.counter += 1
            identifier = "r" + str(self.counter).zfill(6)
        for attempt in range(6):
            self.throttle()
            started = stamp()
            result = call("simulate-custom-policy", parameters, debug=True)
            if result["code"] == "CLIValidationError" and result.get("http_status"):
                # Botocore appends a retry-count clause to exhausted API errors.
                match = re.search(r"An error occurred \(([^)]+)\).*?operation(?: \([^)]*\))?: (.*)", result.get("message", ""))
                if match:
                    result = {"code": match[1], "message": match[2], "http_status": result["http_status"]}
            if result["code"] not in TRANSIENT:
                break
            time.sleep(min(2 ** attempt, 10))
        record = {"id": identifier, "actions": names, "code": result["code"],
                  "http_status": result.get("http_status"), "purpose": purpose, "observed_at": started}
        if attempt:
            record["attempt_count"] = attempt + 1
        if parent:
            record["parent_request_id"] = parent
        if inputs is not None:
            record["input"] = self.sanitize(inputs)
        if profile is not None:
            record["profile"] = profile
        if "message" in result:
            record["message"] = self.sanitize(result["message"])
        if result["code"] in TRANSIENT or result["code"] == "CLIValidationError":
            record["transient"] = True
        if result["code"] == "Success":
            output = result["output"]
            record["result_count"] = len(output.get("EvaluationResults", []))
            record["is_truncated"] = output.get("IsTruncated", False)
        with self.lock:
            self.fixture["requests"].append(record)
        self.checkpoint()
        if result["code"] == "Success" and (result["output"].get("IsTruncated") or result["output"].get("Marker")):
            raise RuntimeError("Unexpected pagination despite MaxItems=1000 and at most 100 actions; preserve checkpoint before resuming")
        if record.get("transient"):
            raise RuntimeError(identifier + " exhausted bounded request retries: " + result["code"])
        return identifier, result

    @staticmethod
    def groups(result, names):
        if result["code"] != "InvalidInput" or "require different authorization information" not in result.get("message", ""):
            return None
        groups = [[name.strip() for name in text.split(",") if name.strip()]
                  for text in re.findall(r"\[([^\]]*)\]", result["message"])]
        flattened = [name for group in groups for name in group]
        if len(groups) < 2 or len(flattened) != len(set(flattened)) or set(flattened) != set(names):
            return None
        return groups

    def finish_actions(self, names, request_id, result, aware=None, grouping_id=None):
        outputs = result.get("output", {}).get("EvaluationResults", [])
        if result["code"] == "Success" and (len(outputs) != len(names) or any(name.lower() != row["EvalActionName"].lower() for name, row in zip(names, outputs))):
            raise RuntimeError(request_id + " response action sequence/count differs from its input")
        records = []
        for index, name in enumerate(names):
            row = {"action": name, "catalogue_index": self.positions[name], "code": result["code"],
                   "http_status": result.get("http_status"), "request_id": request_id}
            if result["code"] == "Success":
                output = outputs[index]
                row.update({"resource_aware": aware, "grouping_request_id": grouping_id,
                            "eval_action_name": output["EvalActionName"],
                            "eval_resource_name_present": "EvalResourceName" in output, "eval_decision": output["EvalDecision"],
                            "resource_specific_results": [{"EvalResourceName": item["EvalResourceName"],
                                                           "EvalResourceDecision": item["EvalResourceDecision"]}
                                                          for item in output.get("ResourceSpecificResults", [])]})
                if "EvalResourceName" in output:
                    row["eval_resource_name"] = output["EvalResourceName"]
            else:
                row["message"] = self.sanitize(result.get("message", ""))
            records.append(row)
        with self.lock:
            self.completed.update({row["action"]: row for row in records})
        self.checkpoint()

    def batch(self, names, parent=None):
        identifier, result = self.request(names, parent)
        if result["code"] != "Success":
            if len(names) == 1:
                self.finish_actions(names, identifier, result)
                return
            groups = self.groups(result, names)
            if groups is None:
                middle = len(names) // 2
                groups = [names[:middle], names[middle:]]
            for group in groups:
                self.batch(group, identifier)
            return
        if ANCHOR in names:
            self.finish_actions(names, identifier, result, True, identifier)
            return
        grouping_id, anchored = self.request(names + [ANCHOR], identifier, purpose="grouping")
        if anchored["code"] == "Success":
            self.finish_actions(names, identifier, result, True, grouping_id)
            return
        groups = self.groups(anchored, names + [ANCHOR])
        if groups is not None and any(group == [ANCHOR] for group in groups):
            self.finish_actions(names, identifier, result, False, grouping_id)
            return
        raise RuntimeError(grouping_id + " did not establish homogeneous simulator grouping")

    def profile_batch(self, profile, names, parent=None):
        parameters = {"PolicyInputList": [ALLOW_ALL], "ActionNames": names, "MaxItems": 1000}
        if profile == "single":
            parameters["ResourceArns"] = COMMON["ResourceArns"][:1]
        identifier, result = self.request(names, parent, parameters, "profile", profile)
        if result["code"] != "Success" and len(names) > 1:
            groups = self.groups(result, names)
            if groups is None:
                middle = len(names) // 2
                groups = [names[:middle], names[middle:]]
            for group in groups:
                self.profile_batch(profile, group, identifier)
            return
        outputs = result.get("output", {}).get("EvaluationResults", [])
        if result["code"] == "Success" and (len(outputs) != len(names) or any(name.lower() != row["EvalActionName"].lower() for name, row in zip(names, outputs))):
            raise RuntimeError(identifier + " profile response action sequence/count differs from its input")
        with self.lock:
            for index, name in enumerate(names):
                value = {"request_id": identifier, "code": result["code"], "http_status": result.get("http_status")}
                if result["code"] == "Success":
                    output = outputs[index]
                    value.update({"eval_action_name": output["EvalActionName"], "eval_decision": output["EvalDecision"],
                                  "eval_resource_name_present": "EvalResourceName" in output,
                                  "resource_specific_results": [{"EvalResourceName": item["EvalResourceName"], "EvalResourceDecision": item["EvalResourceDecision"]}
                                                                for item in output.get("ResourceSpecificResults", [])]})
                    if "EvalResourceName" in output:
                        value["eval_resource_name"] = output["EvalResourceName"]
                else:
                    value["message"] = result.get("message", "")
                    print("terminal profile error", profile, name, result["code"], flush=True)
                self.completed[name][profile + "_result"] = self.sanitize(value)
        self.checkpoint()

    def profiles(self):
        for profile in ("default", "single"):
            pending = [name for name in self.names if profile + "_result" not in self.completed[name]]
            groups = [pending]
            if profile == "single":
                groups = [[name for name in pending if self.completed[name].get("resource_aware") == aware] for aware in (True, False)]
            batches = [group[index:index + 100] for group in groups for index in range(0, len(group), 100)]
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                futures = [executor.submit(self.profile_batch, profile, names) for names in batches]
                for future in concurrent.futures.as_completed(futures):
                    future.result()
            self.fixture["profile_complete"][profile] = True
            self.checkpoint(True)

    def representatives(self):
        cases = [
            ("known_resource_and_global", {**COMMON, "ActionNames": ["s3:GetObject", "iam:ListUsers", "sts:GetCallerIdentity"]}),
            ("global_without_declared_resources", {**COMMON, "ActionNames": ["a2c:GetContainerizationJobDetails", "applicationinsights:AddWorkload"]}),
            ("global_without_declared_resources_anchor", {**COMMON, "ActionNames": ["a2c:GetContainerizationJobDetails", "applicationinsights:AddWorkload", ANCHOR]}),
            ("unknown_control", {**COMMON, "ActionNames": ["stackdsim:Unmodeled"]}),
            ("unknown_control_single", {**COMMON, "ActionNames": ["stackdsim:Unmodeled"], "ResourceArns": COMMON["ResourceArns"][:1]}),
            ("unknown_control_mixed", {**COMMON, "ActionNames": ["stackdsim:Unmodeled", "s3:GetObject"]}),
            ("default_resources", {"PolicyInputList": [ALLOW_ALL], "ActionNames": ["s3:GetObject", "iam:ListUsers", "stackdsim:Unmodeled"], "MaxItems": 1000}),
            ("single_resource", {**COMMON, "ActionNames": ["dynamodb:GetItem", "dynamodb:Query"], "ResourceArns": COMMON["ResourceArns"][:1]}),
            ("duplicate_resource", {**COMMON, "ActionNames": ["dynamodb:GetItem", "dynamodb:Query"], "ResourceArns": [COMMON["ResourceArns"][0]] * 2}),
            ("mixed_partitions", {**COMMON, "ActionNames": ["dynamodb:GetItem", "dynamodb:Query"],
                                  "ResourceArns": ["arn:aws-cn:sqs:cn-north-1:123456789012:one", "arn:aws-us-gov:sqs:us-gov-west-1:123456789012:two"]}),
            ("case_collision", {**COMMON, "ActionNames": ["verifiedpermissions:IsAuthorized", "verifiedpermissions:isauthorized", "verifiedpermissions:IsAuThOrIzEd"]}),
        ]
        default = {"PolicyInputList": [ALLOW_ALL], "MaxItems": 1000,
                   "ActionNames": ["iam:GetUser", "iam:ListUsers", "iam:GetRole", "iam:ListRoles", "iam:GetPolicy", "iam:ListPolicies", "sts:AssumeRole"]}
        user = "arn:aws:iam::111122223333:user/team/CallerName"
        for label, change in (("absent", {}), ("user", {"CallerArn": user}),
                              ("role", {"CallerArn": "arn:aws:iam::111122223333:role/team/CallerRole"}),
                              ("china_user", {"CallerArn": user.replace("arn:aws:", "arn:aws-cn:")}),
                              ("username_context", {"ContextEntries": [{"ContextKeyName": "aws:username", "ContextKeyType": "string", "ContextKeyValues": ["ContextName"]}]}),
                              ("user_username_context", {"CallerArn": user, "ContextEntries": [{"ContextKeyName": "aws:username", "ContextKeyType": "string", "ContextKeyValues": ["ContextName"]}]})):
            cases.append(("default_caller_" + label, {**default, **change}))
        names = ["applicationinsights:AddWorkload", "a2c:GetContainerizationJobDetails", "s3:GetObject", "iam:GetUser"]
        for label, resources in (("omitted", None), ("star", ["*"]), ("duplicate_star", ["*", "*"]),
                                  ("mixed_star", ["*", COMMON["ResourceArns"][0]]), ("single_arn", COMMON["ResourceArns"][:1])):
            parameters = {"PolicyInputList": [ALLOW_ALL], "ActionNames": names, "MaxItems": 1000}
            if resources is not None:
                parameters["ResourceArns"] = resources
            cases.append(("resource_modes_" + label, parameters))
        for name in ("s3:GetObject", "iam:GetUser", "dynamodb:GetItem", "verifiedpermissions:IsAuthorized", "applicationinsights:AddWorkload", "a2c:GetContainerizationJobDetails"):
            service, operation = name.split(":", 1)
            mixed = "".join(character.upper() if index % 2 == 0 else character.lower() for index, character in enumerate(operation))
            for label, variant in (("lowercase_action", service + ":" + operation.lower()), ("mixed_action", service + ":" + mixed), ("uppercase_service", service.upper() + ":" + operation)):
                cases.append(("case_" + service + "_" + label, {**COMMON, "ActionNames": [variant, ANCHOR]}))
        for label, resource in (("exact", "user/"), ("wildcard", "user/*"), ("other_user", "user/OtherUser")):
            cases.append(("default_iam_list_policy_" + label,
                          {"ActionNames": ["iam:ListUsers"], "PolicyInputList": [policy(statement(action="iam:ListUsers", resource="arn:aws:iam::" + self.account + ":" + resource))], "MaxItems": 1000}))
        existing = {row["case"] for row in self.fixture["representative_responses"]}
        for name, parameters in cases:
            if name in existing:
                continue
            identifier, result = self.request(parameters["ActionNames"], inputs=parameters, purpose="representative")
            row = {"case": name, "operation": "SimulateCustomPolicy", "input": parameters, "request_id": identifier, **result}
            normalized = self.sanitize(row)
            self.fixture["representative_responses"].append(normalized)
            self.checkpoint()

    def run(self, representatives_only=False, batch_limit=None):
        process = subprocess.run(["aws", "sts", "get-caller-identity", "--output", "json", "--no-cli-pager"],
                                 capture_output=True, text=True, check=True, timeout=90)
        caller = json.loads(process.stdout)
        self.account, self.caller_arn = caller["Account"], caller["Arn"]
        self.fixture["aws_cli_version"] = subprocess.run(["aws", "--version"], capture_output=True, text=True, check=True).stdout.strip()
        print("credentials verified; read-only simulation capture", flush=True)
        self.checkpoint(True)
        if not representatives_only and self.fixture["profile_complete"]["multiple"]:
            self.profiles()
        self.representatives()
        if representatives_only:
            self.checkpoint(True)
            return
        pending = [name for name in self.names if name not in self.completed]
        batches = [pending[index:index + 99] for index in range(0, len(pending), 99)]
        if batch_limit is not None:
            batches = batches[:batch_limit]
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(self.batch, names) for names in batches]
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as error:
                    self.fixture["failures"].append({"observed_at": stamp(), "message": str(error)})
                    for pending_future in futures:
                        pending_future.cancel()
                    raise
        self.fixture["profile_complete"]["multiple"] = len(self.completed) == len(self.names)
        if self.fixture["profile_complete"]["multiple"]:
            self.profiles()
        self.fixture["capture_complete"] = all(self.fixture["profile_complete"].values())
        self.checkpoint(True)


if __name__ == "__main__":
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", action="store_true", required=True)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--representatives-only", action="store_true")
    parser.add_argument("--batch-limit", type=int)
    parser.add_argument("--account", required=True)
    options = parser.parse_args()
    require_account(options.account)
    capture = Capture(options.resume)
    try:
        capture.run(options.representatives_only, options.batch_limit)
    finally:
        capture.checkpoint(True)
