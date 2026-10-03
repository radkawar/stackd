#!/usr/bin/env python3
"""Read centralized-root metadata and denied requests without changing settings.

Only uniquely named IAM observer users/policies/keys are created. Root feature
mutations are called solely with an observer explicitly denied those actions.
AssumeRoot controls target the management account itself, never a member; no
returned session is used and no root credential or resource policy is modified.
"""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True
from iam_organizations_access_probe import Probe, ROOT, call, operation, stamp, policy, allow

DESTINATION = ROOT / '.stackd/probes/iam/root_access.json'
FEATURE_ACTIONS = ["enable-organizations-root-credentials-management", "disable-organizations-root-credentials-management",
                   "enable-organizations-root-sessions", "disable-organizations-root-sessions"]
DOCUMENTATION = [
    "https://docs.aws.amazon.com/IAM/latest/APIReference/API_" + name + ".html"
    for name in ["EnableOrganizationsRootCredentialsManagement", "DisableOrganizationsRootCredentialsManagement",
                 "EnableOrganizationsRootSessions", "DisableOrganizationsRootSessions", "ListOrganizationsFeatures", "GetAccountProperties"]
] + ["https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoot.html",
     "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-enable-root-access.html",
     "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user-privileged-task.html",
     "https://docs.aws.amazon.com/IAM/latest/UserGuide/security-iam-awsmanpol.html",
     "https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-track-privileged-tasks.html",
     "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-assumedroot",
     "https://docs.aws.amazon.com/organizations/latest/userguide/services-that-can-integrate-iam.html"]


class RootProbe(Probe):
    def __init__(self, output):
        super().__init__(output)
        self.prefix = "stackd-root-access-" + uuid.uuid4().hex[:10]
        self.normalized_prefix = "stackd-root-access-fixture"
        self.journal = ROOT / ".stackd/probes" / (self.prefix + ".json")
        self.limitations = [
            "Existing organization settings, trusted service access, delegated administrators and root credentials are never changed.",
            "Feature enable/disable requests use only an owned observer with explicit Deny; successful feature transitions and disable/re-enable persistence are documentation-only in this capture.",
            "AssumeRoot calls target only the management account or its owned observer ARN. No member account is targeted, no privileged root task is performed, and any unexpected returned credentials are discarded without use.",
            "GetAccountProperties is a separate account configuration map, including RoleManager settings; it is not the centralized-root feature list.",
        ]

    def write(self, cleaned=False):
        data = {"schema_version": 1, "source": "Real AWS IAM/Organizations/STS APIs, commercial partition",
                "probe": "scripts/aws/iam_root_access_probe.py", "aws_cli_version": self.cli_version,
                "started_at": self.started, "finished_at": stamp(), "documentation": DOCUMENTATION,
                "model_source": "clones/aws-sdk-go-v2/service/{iam,sts}/api_op_*.go and generated internal/awsapi contracts",
                "eligibility": self.eligibility, "setup": self.normalize(self.setup), "observations": self.observations,
                "cleanup": self.normalize(self.cleanup), "capture_complete": self.complete, "cleanup_verified": cleaned,
                "sanitization": "Account/organization IDs and owned identities normalized; no credential secrets, root credential details, unrelated principal rows, service integrations or CLI debug logs retained.",
                "limitations": self.limitations}
        self.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.output.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(data, indent=2) + "\n")
        temporary.replace(self.output)

    def request(self, case, service, action, parameters=None, environment=None, credential="original", endpoint=None):
        if action in FEATURE_ACTIONS and (environment is None or credential != "explicit_deny_observer"):
            raise RuntimeError("Feature mutations are restricted to the explicitly denied observer")
        if endpoint is None:
            return self.observe(case, service, action, parameters, environment, credential)
        command = ["aws", service, action, "--cli-input-json", json.dumps(parameters or {}), "--endpoint-url", endpoint,
                   "--region", "us-east-1", "--output", "json", "--no-cli-pager", "--no-paginate", "--debug"]
        response = subprocess.run(command, capture_output=True, text=True, timeout=60, env=environment)
        statuses = re.findall(r'"(?:POST|GET) / HTTP/1\.1" (\d{3})', response.stderr)
        if response.returncode:
            match = re.search(r"An error occurred \(([^)]+)\).*?operation(?: \([^)]*\))?: (.*)", response.stderr)
            result = {"code": match[1] if match else "CLIError", "message": match[2] if match else "CLI rejected request; diagnostics discarded"}
        else:
            result = {"code": "Success", "output": json.loads(response.stdout or "{}")}
        if statuses:
            result["http_status"] = int(statuses[-1])
        row = {"case": case, "service": service, "operation": operation(action), "input": parameters or {},
               "endpoint": endpoint, "region": "us-east-1", "credential": credential, "observed_at": stamp(), **result}
        if self.changes:
            row["state_changes_before"], self.changes = self.changes, []
        self.observations.append(self.normalize(row))
        self.write()
        print(case, result["code"], flush=True)
        return result


def run(probe):
    identity = call("sts", "get-caller-identity")
    if identity["code"] != "Success":
        raise RuntimeError("AWS credentials unavailable; diagnostics discarded")
    identity = identity["output"]
    probe.account = identity["Account"]
    probe.identifiers.update({identity["Arn"]: "<original-caller-arn>", identity["UserId"]: "<original-caller-id>"})
    organization = call("organizations", "describe-organization")
    probe.eligibility = {"caller_is_root": identity["Arn"].endswith(":root"), "organization_read_code": organization["code"]}
    if organization["code"] == "Success":
        organization = organization["output"]["Organization"]
        probe.identifiers[organization["Id"]] = "o-aaaaaaaaaa"
        probe.eligibility.update(management_account=organization.get("ManagementAccountId", organization.get("MasterAccountId")) == probe.account,
                                 feature_set=organization["FeatureSet"])
        services = call("organizations", "list-aws-service-access-for-organization")
        probe.eligibility["trusted_services_read_code"] = services["code"]
        if services["code"] == "Success":
            probe.eligibility["iam_trusted_access"] = any(item["ServicePrincipal"] == "iam.amazonaws.com" for item in services["output"]["EnabledServicePrincipals"])
    probe.request("features_original_before", "iam", "list-organizations-features")
    probe.request("properties_original", "iam", "get-account-properties")
    read_actions = ["iam:ListOrganizationsFeatures", "iam:GetAccountProperties"]
    denied_writes = ["iam:" + operation(action) for action in FEATURE_ACTIONS]
    environments = {}
    for label, document in [
        ("explicit_deny_observer", policy(allow(read_actions), {"Effect": "Deny", "Action": denied_writes + ["organizations:*", "sts:AssumeRoot"], "Resource": "*"})),
        ("no_grants", policy({"Effect": "Deny", "Action": "organizations:*", "Resource": "*"})),
        ("scoped_reads", policy(allow(read_actions, "arn:aws:iam::" + probe.account + ":root"))),
    ]:
        user = probe.user(label)
        probe.inline(user, document)
        env = probe.key(user, label)
        environments[label] = (env, user)
        probe.request("features_" + label, "iam", "list-organizations-features", environment=env, credential=label)
        probe.request("properties_" + label, "iam", "get-account-properties", environment=env, credential=label)
    env, user = environments["explicit_deny_observer"]
    for action in FEATURE_ACTIONS:
        probe.request("denied_" + action.replace("-", "_"), "iam", action, environment=env, credential="explicit_deny_observer")
    audit = "arn:aws:iam::aws:policy/root-task/IAMAuditRootUserCredentials"
    request = {"TargetPrincipal": probe.account, "TaskPolicyArn": {"arn": audit}}
    probe.request("assume_root_observer_denied", "sts", "assume-root", request, env, "explicit_deny_observer")
    if probe.eligibility.get("management_account") and not probe.eligibility["caller_is_root"]:
        for label, parameters in [
            ("management_id", request),
            ("management_root_arn", {**request, "TargetPrincipal": "arn:aws:iam::" + probe.account + ":root"}),
            ("owned_user_arn", {**request, "TargetPrincipal": user["Arn"]}),
            ("duration_zero", {**request, "DurationSeconds": 0}),
            ("duration_over_limit", {**request, "DurationSeconds": 901}),
            ("invalid_task_policy", {**request, "TaskPolicyArn": {"arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}}),
            ("task_policy_missing_arn", {"TargetPrincipal": probe.account, "TaskPolicyArn": {}}),
        ]:
            probe.request("assume_root_" + label, "sts", "assume-root", parameters)
        probe.request("assume_root_global_endpoint", "sts", "assume-root", request, endpoint="https://sts.amazonaws.com")
    probe.request("features_original_after", "iam", "list-organizations-features")


def main():
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DESTINATION)
    parser.add_argument("--append-public-policies", action="store_true", help="Append current public root-task policy documents to an existing completed capture")
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    require_account(args.account)
    probe = RootProbe(args.output)
    if args.append_public_policies:
        previous = json.loads(args.output.read_text())
        if not previous["capture_complete"] or not previous["cleanup_verified"]:
            parser.error("Public policy append requires a completed capture with verified cleanup")
        probe.started = previous["started_at"]
        probe.setup = previous["setup"]
        probe.observations = previous["observations"]
        probe.cleanup = previous["cleanup"]
        probe.eligibility = previous["eligibility"]
        probe.limitations = previous["limitations"]
    try:
        if args.append_public_policies:
            for name in ["IAMAuditRootUserCredentials", "IAMCreateRootUserPassword", "IAMDeleteRootUserCredentials", "S3UnlockBucketPolicy", "SQSUnlockQueuePolicy"]:
                arn = "arn:aws:iam::aws:policy/root-task/" + name
                metadata = probe.request("public_policy_" + name, "iam", "get-policy", {"PolicyArn": arn})
                if metadata["code"] == "Success":
                    probe.request("public_policy_version_" + name, "iam", "get-policy-version", {"PolicyArn": arn, "VersionId": metadata["output"]["Policy"]["DefaultVersionId"]})
        else:
            run(probe)
        probe.complete = True
    finally:
        probe.finish()


if __name__ == "__main__":
    main()
