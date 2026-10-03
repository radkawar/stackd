#!/usr/bin/env python3
"""Observe real IAM tag behavior on temporary owned resources, then delete them.

Uses the AWS CLI credential configuration. Creates one user, role, customer
policy and unassigned virtual MFA device. The generated MFA seed exists only
inside a deleted temporary directory; fixture output contains no credentials.
"""

import datetime
import json
import pathlib
import secrets
import tempfile

from aws_cli import run as run_cli, result as cli_result, error_code


def call(operation, parameters=None, extra=()):
    process = run_cli("iam", operation, parameters, options=["--no-paginate", *extra])
    if process.returncode:
        return {"code": error_code(process)}
    return cli_result(process)


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    require_account(probe_args.account)
    name = "stackd-tags-probe-" + secrets.token_hex(8)
    observations = []
    owned = []
    case_tags = [{"Key": "Team", "Value": "One"}, {"Key": "team", "Value": "Two"}]

    def observe(case, operation, parameters=None, shape=None, extra=()):
        result = call(operation, parameters, extra)
        entry = {"case": case, "operation": operation, "code": result["code"], "automatic_pagination": False}
        if result["code"] == "Success":
            data = result["output"].get(shape, {}) if shape else result["output"]
            entry["wire_fields"] = sorted(data)
            if "Tags" in data:
                entry["tags"] = data["Tags"]
            if "IsTruncated" in data:
                entry["is_truncated"] = data["IsTruncated"]
        observations.append(entry)
        print(f"{case}: {result['code']}", flush=True)
        return result

    def require(result):
        if result["code"] != "Success":
            raise RuntimeError("Probe setup failed: " + result["code"])
        return result["output"]

    try:
        require(observe("create_user", "create-user", {"UserName": name, "Tags": case_tags[:1]}, "User"))
        owned.append(("delete-user", "get-user", {"UserName": name}))
        observe("user_replace_key_case", "tag-user", {"UserName": name, "Tags": case_tags[1:]})
        observe("user_case_result", "list-user-tags", {"UserName": name})
        observe("user_duplicate_case_keys", "tag-user", {"UserName": name, "Tags": [{"Key": "DUP", "Value": "one"}, {"Key": "dup", "Value": "two"}]})
        for case, tag in [
            ("user_reserved_key", {"Key": "aws:reserved", "Value": "one"}),
            ("user_reserved_key_upper", {"Key": "AWS:reserved", "Value": "one"}),
            ("user_reserved_value", {"Key": "reservedvalue", "Value": "aws:reserved"}),
            ("user_reserved_value_upper", {"Key": "reservedvalueupper", "Value": "AWS:reserved"}),
            ("user_whitespace_key", {"Key": "white\tkey", "Value": "line\nvalue"}),
        ]:
            observe(case, "tag-user", {"UserName": name, "Tags": [tag]})
        observe("user_empty_tag_list", "tag-user", {"UserName": name, "Tags": []})
        observe("user_empty_untag_list", "untag-user", {"UserName": name, "TagKeys": []})
        observe("user_untag_reserved_key", "untag-user", {"UserName": name, "TagKeys": ["aws:reserved"]})
        observe("user_untag_duplicate_case", "untag-user", {"UserName": name, "TagKeys": ["Team", "team"]})
        tags = require(observe("user_tags_after_removal", "list-user-tags", {"UserName": name}))["Tags"]
        require(call("untag-user", {"UserName": name, "TagKeys": [tag["Key"] for tag in tags]}))
        fifty = [{"Key": f"key{i:02d}", "Value": "v"} for i in range(50)]
        require(observe("user_fill_fifty_tags", "tag-user", {"UserName": name, "Tags": fifty}))
        observe("user_exceed_total_tag_quota", "tag-user", {"UserName": name, "Tags": [{"Key": "extra", "Value": "v"}, {"Key": "key00", "Value": "changed"}]})
        observe("user_tags_after_quota_rejection", "list-user-tags", {"UserName": name, "MaxItems": 100})
        observe("user_exceed_request_tag_limit", "tag-user", {"UserName": name, "Tags": fifty + [{"Key": "extra", "Value": "v"}]})
        trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
        require(observe("create_role", "create-role", {"RoleName": name, "AssumeRolePolicyDocument": json.dumps(trust), "Tags": case_tags[:1]}, "Role"))
        owned.append(("delete-role", "get-role", {"RoleName": name}))
        observe("role_replace_key_case", "tag-role", {"RoleName": name, "Tags": case_tags[1:]})
        observe("role_case_result", "list-role-tags", {"RoleName": name})
        observe("get_role_tags", "get-role", {"RoleName": name}, "Role")
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iam:GetUser", "Resource": "*"}]}
        created = require(observe("create_policy_case_variants", "create-policy", {"PolicyName": name, "PolicyDocument": json.dumps(policy), "Tags": case_tags}, "Policy"))
        arn = created["Policy"]["Arn"]
        owned.append(("delete-policy", "get-policy", {"PolicyArn": arn}))
        observe("get_policy_tags", "get-policy", {"PolicyArn": arn}, "Policy")
        observe("list_policy_tags", "list-policy-tags", {"PolicyArn": arn})
        observe("policy_reserved_value", "tag-policy", {"PolicyArn": arn, "Tags": [{"Key": "reservedvalue", "Value": "aws:reserved"}]})
        with tempfile.TemporaryDirectory(prefix="stackd-mfa-probe-") as directory:
            mfa = require(observe("create_mfa_direct_cli_arguments", "create-virtual-mfa-device", shape="VirtualMFADevice", extra=("--virtual-mfa-device-name", name, "--tags", "Key=Team,Value=One", "Key=team,Value=Two", "--bootstrap-method", "Base32StringSeed", "--outfile", directory + "/seed")))
            serial = mfa["VirtualMFADevice"]["SerialNumber"]
            owned.append(("delete-virtual-mfa-device", "list-mfa-device-tags", {"SerialNumber": serial}))
            observe("mfa_case_result", "list-mfa-device-tags", {"SerialNumber": serial})
            observe("mfa_reserved_value", "tag-mfa-device", {"SerialNumber": serial, "Tags": [{"Key": "reservedvalue", "Value": "aws:reserved"}]})
            observe("mfa_reserved_key", "tag-mfa-device", {"SerialNumber": serial, "Tags": [{"Key": "aws:reserved", "Value": "One"}]})
    finally:
        cleanup = []
        for remove, read, parameters in reversed(owned):
            cleanup.append({"operation": remove, "code": call(remove, parameters)["code"]})
            cleanup.append({"operation": read, "code": call(read, parameters)["code"]})
        fixture = {
            "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "source": "Real AWS IAM API; only uniquely named owned resources. Credential material and account identifiers omitted.",
            "observations": observations,
            "cleanup": cleanup,
            "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html", "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html"],
            "limits": ["AWS CLI automatic pagination disabled; response field observations reflect single API calls."],
        }
        destination = pathlib.Path(__file__).resolve().parents[2] / '.stackd/probes/iam/tags_aws.json'
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(fixture, indent=2) + "\n")
        if any(entry["code"] != ("Success" if index % 2 == 0 else "NoSuchEntity") for index, entry in enumerate(cleanup)):
            raise RuntimeError("Probe cleanup failed; inspect fixture cleanup entries and stackd-tags-probe resources")


if __name__ == "__main__":
    main()
