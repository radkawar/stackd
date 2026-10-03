#!/usr/bin/env python3
"""Capture owned Gateway management or authorizer-role STS events; creates no resources."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path

from aws_cli import call, observe
from cloudtrail_events import CollectionError, collect_history


def captures(source):
    yield source
    for previous in source.get("prior_captures", []):
        yield from captures(previous)
    if "fresh_null_capture" in source:
        yield from captures(source["fresh_null_capture"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--input", type=Path, nargs="+", default=[Path(".stackd/probes/apigateway/deployed_lambda_authorization.json")])
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/apigateway/cloudtrail_deployed.json"))
    parser.add_argument("--role-assumptions", action="store_true", help="Correlate API Gateway STS assumptions by exact owned role ARN")
    args = parser.parse_args()
    if args.output.exists():
        raise RuntimeError("Refusing to overwrite native evidence")
    sources = [(path, json.loads(path.read_text())) for path in args.input]
    account, region = args.account, sources[0][1]["region"]
    rows, owned_roles = [], {}
    for path, source in sources:
        if source["account"] != account or source["region"] != region:
            raise RuntimeError("Sources must use the same account and region")
        for capture in captures(source):
            rows.extend(capture["observations"])
            for row in capture["observations"]:
                if row["service"] == "iam" and row["operation"] == "CreateRole":
                    role = row["result"].get("output", {}).get("Role", {}).get("Arn")
                    if role:
                        owned_roles[role] = {"source": str(path), "capture": capture["prefix"]}
    if not args.role_assumptions:
        rows = [row for row in rows if row["service"] in ("apigateway", "apigatewayv2")]
    elif not owned_roles:
        raise RuntimeError("No successfully created owned roles in the supplied captures")
    by_request = {row["result"]["request_id"]: row for row in rows if row["result"].get("request_id")}
    instant = datetime.datetime.fromisoformat
    start = min(instant(row["started_at"]) for row in rows).replace(microsecond=0)
    end = max(instant(row["finished_at"]) for row in rows).replace(microsecond=0) + datetime.timedelta(seconds=1)
    env = dict(os.environ, AWS_REGION=region, AWS_DEFAULT_REGION=region, AWS_MAX_ATTEMPTS="1")
    identity = observe("sts", "get-caller-identity", env=env)
    if identity.get("output", {}).get("Account") != account:
        raise RuntimeError("Account does not match owned capture")
    source_name = "sts.amazonaws.com" if args.role_assumptions else "apigateway.amazonaws.com"
    correlation = ("Exact successfully created role ARN and apigateway.amazonaws.com service actor; "
                   "no association with an individual HTTP request is inferred." if args.role_assumptions
                   else "Exact captured SDK response request ID only; no temporal ownership inference.")
    evidence = {"sources": [str(path) for path, _ in sources], "account": account, "region": region,
        "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_source": source_name, "bounds": {"pages": 8, "events_per_page": 50},
        "lookup_window": {"start": start.isoformat(), "end": end.isoformat()},
        "correlation": correlation,
        "redaction": "Redacts secret access keys/session tokens; hashes access key identifiers and client IP addresses.",
        "documentation": "https://docs.aws.amazon.com/apigateway/latest/developerguide/cloudtrail.html",
        "probe_source": Path(__file__).read_text(), "events": [], "lookup_pages": [],
        "cleanup": "Read-only event-history lookup; no resources created or changed."}

    def redact(value):
        if isinstance(value, dict):
            return {key: ("<redacted>" if key.lower() in ("secretaccesskey", "sessiontoken") and item is not None
                          else "<probe-redacted-sha256:" + hashlib.sha256(json.dumps(item, sort_keys=True).encode()).hexdigest() + ">"
                          if key.lower() in ("accesskeyid", "sourceipaddress") and item is not None else redact(item))
                    for key, item in value.items()}
        if isinstance(value, list):
            return [redact(item) for item in value]
        return value

    def owned_assumption(event):
        role = (event.get("requestParameters") or {}).get("roleArn")
        return (role in owned_roles and event.get("eventName") == "AssumeRole"
                and (event.get("userIdentity") or {}).get("invokedBy") == "apigateway.amazonaws.com")

    audit = None
    try:
        audit = collect_history(
            lambda parameters: call("cloudtrail", "lookup-events", parameters, env=env,
                                    paginate=False, error_format="json"),
            {} if args.role_assumptions else {request_id: row["label"] for request_id, row in by_request.items()},
            start_time=start, end_time=end, max_pages=8,
            event_sources=() if args.role_assumptions else (source_name,),
            lookup_attributes=({"AttributeKey": "EventName", "AttributeValue": "AssumeRole"},) if args.role_assumptions else (),
            related=owned_assumption if args.role_assumptions else None)
    except CollectionError as error:
        audit = error.result
        raise
    finally:
        if audit is not None:
            for match in audit["events"]:
                event = match["event"]
                if args.role_assumptions:
                    role = event["requestParameters"]["roleArn"]
                    row = {**owned_roles[role], "role_arn": role}
                else:
                    source_row = by_request[event["requestID"]]
                    row = {key: source_row[key] for key in ("label", "service", "operation")}
                evidence["events"].append({**row, "call_label": match["call_label"], "event": redact(event)})
            evidence["lookup_pages"] = audit["pages"]
            for key in ("observations", "missing_request_ids", "missing_calls", "page_cap_reached", "partial", "boundary", "errors"):
                evidence[key] = audit[key]
            if not args.role_assumptions:
                evidence["missing_observations"] = audit["missing_calls"]
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(evidence, indent=2)+"\n")
    print(json.dumps({"correlated": len(evidence["events"]), "missing": evidence.get("missing_observations"),
                      "page_cap_reached": audit["page_cap_reached"]}))


if __name__ == "__main__":
    main()
