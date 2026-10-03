#!/usr/bin/env python3
"""Read-only capture of Account legacy enum rejection boundaries."""

import datetime
import json
import pathlib

from aws_cli import AWSCLIError, call


def main():
    import argparse
    from aws_cli import require_account
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    probe_args = parser.parse_args()
    account = require_account(probe_args.account)["Account"]
    fixture = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "source": "AWS Account Management, authenticated management-account caller; read-only",
               "observations": []}
    cases = [("contact_"+kind, "get-alternate-contact", {"AlternateContactType": kind}) for kind in ["operations", "OTHER", "Billing"]]
    cases += [("filter_"+str(i), "list-regions", {"RegionOptStatusContains": states})
              for i, states in enumerate([["enabled"], ["UNKNOWN"], ["ENABLED", "UNKNOWN"], ["ENABLED", "ENABLED"]])]
    for name, operation, params in cases:
        row = {"case": name, "operation": operation, "input": params}
        try:
            result = call("account", operation, params, paginate=False, error_format="json")
            if "AlternateContact" in result:
                result = {"AlternateContactType": result["AlternateContact"]["AlternateContactType"]}
            row.update(code="Success", output=result)
        except AWSCLIError as error:
            parsed = error.details
            row.update(code=parsed["Code"], error=parsed)
        fixture["observations"].append(row)
        print(name+": "+row["code"], flush=True)
    path = pathlib.Path(__file__).resolve().parents[2] / '.stackd/probes/account/validation.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(fixture, indent=2).replace(account, "111111111111")+"\n")


if __name__ == "__main__":
    main()
