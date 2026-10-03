#!/usr/bin/env python3
"""Observe asynchronous failures using an already registered account email.

Creates request-status history, not a new AWS account. It deliberately does not
test successful creation, account closure or changes to organization settings.
"""

import concurrent.futures
import datetime
import json
import time
import uuid

from aws_cli import call
from organizations_inputs_probe import probe_parser, verified_account, capture_path


def main():
    args = probe_parser("organizations_account_creation.json").parse_args()
    verified_account(args.account)
    organization = call("organizations", "describe-organization")["Organization"]
    before = call("organizations", "list-accounts")["Accounts"]
    account = next(a for a in before if a["Id"] == organization["MasterAccountId"] and a["State"] == "ACTIVE")
    name = "stackd-existing-email-" + uuid.uuid4().hex[:12]
    parameters = {"AccountName": name, "Email": account["Email"]}
    traces = []
    submission_errors = []
    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(call, "organizations", "create-account", parameters) for _ in range(2)]
        for future in futures:
            try:
                result = future.result()["CreateAccountStatus"]
            except RuntimeError as error:
                submission_errors.append(str(error))
                print("CreateAccount submission rejected", flush=True)
                continue
            traces.append({"initial": result, "polls": []})
            print(f"CreateAccount returned {result['State']}", flush=True)
    remaining = list(traces)
    while remaining:
        if time.monotonic() - started > 240:
            raise RuntimeError("Account-creation requests did not finish within the probe deadline")
        for trace in list(remaining):
            status = call("organizations", "describe-create-account-status", {
                "CreateAccountRequestId": trace["initial"]["Id"],
            })["CreateAccountStatus"]
            trace["polls"].append(status)
            if status["State"] != "IN_PROGRESS":
                if status["State"] != "FAILED":
                    raise RuntimeError("An existing-email request unexpectedly created an account")
                remaining.remove(trace)
                print(f"Creation finished: {status.get('FailureReason')}", flush=True)
        if remaining:
            time.sleep(1)
    listed = call("organizations", "list-create-account-status", {"States": ["FAILED"]})["CreateAccountStatuses"]
    own_ids = {trace["initial"]["Id"] for trace in traces}
    listed = [status for status in listed if status["Id"] in own_ids]
    after = call("organizations", "list-accounts")["Accounts"]
    unchanged = {a["Id"] for a in before} == {a["Id"] for a in after}
    if not unchanged:
        raise RuntimeError("The organization account set changed during the probe")
    if not traces:
        raise RuntimeError("No accepted account-creation request: " + "; ".join(submission_errors))
    observations = {"requests": traces, "submission_errors": submission_errors, "listed_failures": listed}
    serialized = json.dumps(observations).replace(name, "OWNED_REQUEST").replace(account["Email"], "REGISTERED_EMAIL")
    for index, trace in enumerate(traces):
        serialized = serialized.replace(trace["initial"]["Id"], f"JOB_{index + 1}")
    fixture = {
        "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": "AWS Organizations CreateAccount/DescribeCreateAccountStatus/ListCreateAccountStatus using the active management account's already registered email",
        "comparison": "Initial and terminal states, response field presence, failure reason, server timestamps and failed-list projection; request IDs/names/email normalized",
        "limitations": "Failed creation only; no successful account creation, account initialization timing or account closure was tested.",
        "observations": json.loads(serialized),
        "cleanup": {"account_set_unchanged": unchanged, "all_owned_requests_failed": True,
                    "note": "AWS retains request-status history; no deletion API exists for these records."},
    }
    destination = capture_path(args.output)
    destination.write_text(json.dumps(fixture, indent=2) + "\n")
    print(f"Wrote {destination}", flush=True)


if __name__ == "__main__":
    main()
