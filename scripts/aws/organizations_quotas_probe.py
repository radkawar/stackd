#!/usr/bin/env python3
"""Read Organizations' default and applied account quotas without changing them."""

import datetime
import json
import os

from aws_cli import call
from organizations_inputs_probe import probe_parser, verified_account, capture_path


def account_quota(operation):
    environment = dict(os.environ, AWS_DEFAULT_REGION="us-east-1", AWS_REGION="us-east-1")
    values = call("service-quotas", operation, {"ServiceCode": "organizations"}, env=environment)["Quotas"]
    quota = next(value for value in values if value["QuotaName"] == "Maximum number of accounts")
    return {key: quota[key] for key in ("QuotaName", "QuotaCode", "Value", "Adjustable", "GlobalQuota")}


def main():
    args = probe_parser("organizations_quotas.json").parse_args()
    verified_account(args.account)
    fixture = {
        "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": "AWS Service Quotas ListAWSDefaultServiceQuotas and ListServiceQuotas for Organizations in us-east-1, using the management account",
        "observations": {
            "default": account_quota("list-aws-default-service-quotas"),
            "applied": account_quota("list-service-quotas"),
        },
        "limitations": "Read-only quota values; no limit was changed and account creation at the applied limit was not attempted.",
        "cleanup": "No resources, quota requests or organization settings were changed.",
    }
    destination = capture_path(args.output)
    destination.write_text(json.dumps(fixture, indent=2) + "\n")
    print(f"Wrote {destination}")


if __name__ == "__main__":
    main()
