#!/usr/bin/env python3
"""Read bounded CloudTrail event-history pages for an owned Cognito login capture.

Creates no resources. Requires the shared AWS CLI helper and the account/region
from the input capture. Native HIDDEN_DUE_TO_SECURITY_REASONS markers are kept;
credential identifiers and source IPs receive explicit probe-redaction markers.
"""
import argparse
from collections import Counter
import datetime
import hashlib
import json
import os
from pathlib import Path

from aws_cli import call, observe
from cloudtrail_events import CollectionError, collect_history

HIDDEN = "HIDDEN_DUE_TO_SECURITY_REASONS"
SECRET_KEYS = {"accesstoken", "idtoken", "refreshtoken", "token", "password", "temporarypassword",
               "new_password", "clientsecret", "secret_hash", "session", "authparameters",
               "challengeresponses", "secret_block", "password_claim_signature", "password_claim_secret_block"}
CORRELATION_FIELDS = ("ClientId", "UserPoolId", "AuthFlow", "ChallengeName", "ClientName", "PoolName")
CORRELATION_LIMITATION = "Only exact captured response request IDs assign call labels; every distinct CloudTrail eventID for a request is retained. Legacy operation/result/field/time matches remain uncorrelated temporal diagnostics, never asserted as per-call ownership."


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def instant(value):
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))


def candidate_labels(event, observations):
    event_time = instant(event["eventTime"])
    event_code = event.get("errorCode") or "Success"
    request = event.get("requestParameters") or {}
    labels = []
    for item in observations:
        request_id = item["result"].get("request_id")
        if request_id:
            if request_id == event.get("requestID") and item["operation"] == event["eventName"]:
                labels.append(item["label"])
            continue
        if item["operation"] != event["eventName"] or item["result"]["code"] != event_code:
            continue
        if not (instant(item["started_at"]).replace(microsecond=0) <= event_time
                <= instant(item["finished_at"]).replace(microsecond=0)):
            continue
        parameters = item["input"]
        compatible = True
        for name in CORRELATION_FIELDS:
            cloudtrail_name = name[0].lower() + name[1:]
            if name not in parameters and cloudtrail_name not in request:
                continue
            if name not in parameters or cloudtrail_name not in request or parameters[name] != request[cloudtrail_name]:
                compatible = False
                break
        if compatible:
            labels.append(item["label"])
    return labels


def correlate(evidence, observations):
    records = evidence["events"] + evidence["temporal_candidates"]
    requests = {item["result"]["request_id"]: item["label"] for item in observations if item["result"].get("request_id")}
    for record in records:
        label = requests.get(record["event"].get("requestID"))
        record["call_label"] = label
        record["candidate_observation_labels"] = [label] if label is not None else []
        record["temporal_candidate_observation_labels"] = candidate_labels(record["event"], observations) if label is None else []
    evidence["summary"]["uniquely_correlated_events"] = sum(record["call_label"] is not None for record in records)
    evidence["summary"]["uncorrelated_events"] = sum(record["call_label"] is None for record in records)
    evidence["limitations"][1] = CORRELATION_LIMITATION
    evidence["correlation"] = {
        "processed_at": now(), "policy": CORRELATION_LIMITATION, "request_fields": list(CORRELATION_FIELDS),
        "source_path": str(Path(__file__)),
        "native_event_documents_modified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", help="Required for native capture; unused by --recorrelate")
    parser.add_argument("--input", type=Path, default=Path(".stackd/probes/cognito/login_workflows.json"))
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/cognito/cloudtrail_login.json"))
    parser.add_argument("--max-pages", type=int, default=8)
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--wait-seconds", type=int, default=15)
    parser.add_argument("--recorrelate", action="store_true", help="Correct only derived labels in an existing output; no AWS calls")
    args = parser.parse_args()
    if not 1 <= args.max_pages <= 8 or not 1 <= args.rounds <= 3 or not 0 <= args.wait_seconds <= 30:
        raise ValueError("Bounds: 1-8 pages, 1-3 rounds, 0-30 seconds between rounds")
    if args.recorrelate:
        source = json.loads(args.input.read_text())
        evidence = json.loads(args.output.read_text())
        if (source["account"] != evidence["account"] or source["region"] != evidence["region"]
                or set(source["resources"]["pools"]) != set(evidence["scope"]["owned_identifiers"]["pool"])):
            raise RuntimeError("Input capture identifies different owned resources")
        correlate(evidence, source["observations"])
        args.output.write_text(json.dumps(evidence, indent=2) + "\n")
        print(json.dumps({key: evidence["summary"][key] for key in ("uniquely_correlated_events", "uncorrelated_events")}))
        return
    if not args.account:
        parser.error("--account is required for native capture")
    if args.output.exists():
        raise RuntimeError("Refusing to overwrite evidence; choose a new output")
    source = json.loads(args.input.read_text())
    if source["account"] != args.account:
        raise RuntimeError("Input capture does not match --account")
    env = dict(os.environ, AWS_REGION=source["region"], AWS_DEFAULT_REGION=source["region"], AWS_MAX_ATTEMPTS="2")
    identity = observe("sts", "get-caller-identity", env=env)
    if identity.get("output", {}).get("Account") != args.account:
        raise RuntimeError("Native account does not match input capture")
    observations = source["observations"]
    request_ids = {item["result"]["request_id"]: item["label"] for item in observations if item["result"].get("request_id")}
    targets = {item["operation"] for item in observations}
    start = min(instant(item["started_at"]) for item in observations).replace(microsecond=0)
    end = max(instant(item["finished_at"]) for item in observations).replace(microsecond=0) + datetime.timedelta(seconds=1)
    identifiers = {"pool": set(source["resources"]["pools"]), "client": set(), "sub": set(), "prefix": {source["prefix"]}}

    def gather(value):
        if isinstance(value, dict):
            if isinstance(value.get("ClientId"), str):
                identifiers["client"].add(value["ClientId"])
            if value.get("Name") == "sub" and isinstance(value.get("Value"), str):
                identifiers["sub"].add(value["Value"])
            if isinstance(value.get("sub"), str):
                identifiers["sub"].add(value["sub"])
            for item in value.values():
                gather(item)
        elif isinstance(value, list):
            for item in value:
                gather(item)

    gather(source)
    evidence = {
        "service": "cloudtrail", "event_source": "cognito-idp.amazonaws.com", "captured_at": now(),
        "source": "Native AWS CloudTrail LookupEvents via scripts/aws/aws_cli.py, automatic pagination disabled",
        "input_capture": {"path": str(args.input),
                          "captured_at": source["captured_at"], "completed_at": source.get("completed_at")},
        "account": source["account"], "region": source["region"], "identity": identity,
        "documentation": ["https://docs.aws.amazon.com/cognito/latest/developerguide/logging-using-cloudtrail.html",
                          "https://docs.aws.amazon.com/cognito/latest/developerguide/understanding-amazon-cognito-entries.html"],
        "scope": {"owned_identifiers": {key: sorted(values) for key, values in identifiers.items()},
                  "start_time": start.isoformat(), "end_time": end.isoformat()},
        "bounds": {"max_pages_per_round": args.max_pages, "max_rounds": args.rounds, "max_events_per_page": 50,
                   "wait_seconds_between_rounds": args.wait_seconds},
        "redaction": "Native HIDDEN_DUE_TO_SECURITY_REASONS values preserved exactly. Probe hashes accessKeyId/AccessKeyId and sourceIPAddress and any unexpectedly unmasked secrets; paths recorded per event.",
        "limitations": ["LookupEvents provides eventual event history, not proof every API attempt has an event.",
                        CORRELATION_LIMITATION,
                        "Events without an owned pool/client/sub/prefix or captured request ID remain separate temporal candidates, never asserted as owned events.",
                        "Availability lag is measured from capture completion to lookup, not the exact first instant CloudTrail published the event.",
                        "No trail, log group, subscription, or other infrastructure created; no new Cognito operations executed."],
        "lookup_pages": [], "events": [], "temporal_candidates": [], "summary": {},
        "probe_source": {"path": str(Path(__file__)), "text": Path(__file__).read_text()}}

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(evidence, indent=2) + "\n")

    def sanitize(value, paths, path=""):
        if isinstance(value, dict):
            output = {}
            for key, item in value.items():
                where = path + "/" + key
                if (key.lower() in SECRET_KEYS or key.lower() in {"accesskeyid", "sourceipaddress"}) and item != HIDDEN and item is not None:
                    encoded = json.dumps(item, sort_keys=True).encode()
                    output[key] = "<probe-redacted-" + key.lower() + "-sha256:" + hashlib.sha256(encoded).hexdigest() + ">"
                    paths.append(where)
                else:
                    output[key] = sanitize(item, paths, where)
            return output
        if isinstance(value, list):
            return [sanitize(item, paths, path + "/" + str(index)) for index, item in enumerate(value)]
        return value

    def ownership_matches(event):
        raw = json.dumps(event)
        matches = {key: sorted(value for value in values if value in raw) for key, values in identifiers.items()}
        matches = {key: values for key, values in matches.items() if values}
        if event.get("requestID") in request_ids:
            matches["request_id"] = [event["requestID"]]
        return matches

    audit = None
    try:
        audit = collect_history(
            lambda parameters: call("cloudtrail", "lookup-events", parameters, env=env,
                                    paginate=False, error_format="json"),
            request_ids, start_time=start, end_time=end, event_sources=("cognito-idp.amazonaws.com",),
            max_pages=args.max_pages, rounds=args.rounds, wait_seconds=args.wait_seconds,
            related=lambda event: bool(ownership_matches(event) or candidate_labels(event, observations)))
    except CollectionError as error:
        audit = error.result
        raise
    finally:
        if audit is not None:
            pages = {}
            for page in audit["pages"]:
                projected = {**page, "code": "Success",
                             "requested_next_token": bool(page["request"].get("NextToken")),
                             "returned_event_count": page["returned"], "has_next_token": page["has_next"],
                             "owned_matches": 0, "temporal_matches": 0,
                             "excluded": page["returned"] - page["matched"] - page.get("duplicates", 0)}
                pages[(page["round"], page["page"])] = projected
                evidence["lookup_pages"].append(projected)
            for match in audit["events"]:
                event = match["event"]
                matches = ownership_matches(event)
                bucket = "events" if matches else "temporal_candidates"
                page = pages[(match["lookup_round"], match["lookup_page"])]
                page["owned_matches" if matches else "temporal_matches"] += 1
                paths = []
                evidence[bucket].append({
                    "lookup_metadata": sanitize(match["lookup_metadata"], paths, "/lookup_metadata"),
                    "event": sanitize(event, paths, "/event"), "ownership_matches": matches,
                    "call_label": match["call_label"], "candidate_observation_labels": [],
                    "probe_redacted_paths": paths, "first_observed_at": match["first_observed_at"]})
            for error in audit["errors"]:
                details = error.get("details") or (error.get("response") or {}).get("Error", {})
                evidence["lookup_pages"].append({
                    "round": error.get("round"), "page": error.get("page"),
                    "started_at": error.get("started_at"), "finished_at": error["at"],
                    "code": details.get("Code", error["type"]), "error": error,
                    "requested_next_token": bool(error.get("request", {}).get("NextToken"))})
            for key in ("observations", "missing_request_ids", "missing_calls", "page_cap_reached", "partial", "boundary", "errors"):
                evidence[key] = audit[key]
            all_records = evidence["events"] + evidence["temporal_candidates"]
            names = Counter(item["event"]["eventName"] for item in evidence["events"])
            recorded = set(names)
            recorded_requests = {item["event"].get("requestID") for item in evidence["events"]}
            evidence["summary"] = {
                "owned_event_count": len(evidence["events"]), "temporal_candidate_count": len(evidence["temporal_candidates"]),
                "owned_event_names": dict(sorted(names.items())), "page_cap_reached": audit["page_cap_reached"],
                "observed_identity_shapes": sorted({json.dumps(item["event"]["userIdentity"], sort_keys=True) for item in all_records}),
                "owned_events_with_resources_field": sum("resources" in item["event"] for item in evidence["events"]),
                "owned_events_with_sub": sum("sub" in (item["event"].get("additionalEventData") or {}) for item in evidence["events"]),
                "target_operations_not_observed": sorted(targets - recorded),
                "target_request_ids_not_observed": sorted(request_ids.keys() - recorded_requests),
                "lookup_started_seconds_after_login_completion": (instant(evidence["captured_at"]) - instant(source["completed_at"])).total_seconds(),
                "completed_at": now(), "cleanup": "Read-only lookup; no resources created or changed."}
            correlate(evidence, observations)
            save()
    print(json.dumps(evidence["summary"], indent=2), flush=True)


if __name__ == "__main__":
    main()
