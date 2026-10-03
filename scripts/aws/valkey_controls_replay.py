#!/usr/bin/env python3
"""Replay calibrated free controls through official signed SDK requests."""
import json
from pathlib import Path

from botocore.exceptions import ClientError


def replay(app):
    root = Path(__file__).resolve().parents[2] / "testdata/aws/valkey"
    results, excluded = [], []
    app.report["observations"]["native_fixture_replay"] = results
    app.report["observations"]["native_fixture_exclusions"] = excluded
    owned = set()
    expected_audit = {v["event"]["requestID"]: v["event"] for v in json.loads((root / "pagination_audit.json").read_text())["history"]["events"]}
    for filename in ("elasticache_pagination.json", "elasticache_users_pagination.json", "controls_valid.json", "memorydb_controls.json", "pagination.json", "filters.json"):
        fixture = json.loads((root / filename).read_text())
        expected_audit.update({v["event"]["requestID"]: v["event"] for v in fixture.get("history", {}).get("events", [])})
        for row in fixture["calls"]:
            case = row["case"]
            if row["code"] == "InternalFailure":
                excluded.append({"case": case, "reason": "native internal error is retained as observed, not reproduced as a stable customer contract; local zero unfiltered page size is explicitly rejected"})
                continue
            if "default-version" in case:
                excluded.append({"case": case, "reason": "local engine is pinned Valkey 8.1.6, not the changing AWS default version"})
                continue
            if any(value in case for value in ("cleanup", "absence", "recovery")):
                excluded.append({"case": case, "reason": "native asynchronous user propagation timing; cleanup is independently exercised below"})
                continue
            service, operation = row["service"], row["operation"]
            client = app.ec if service == "elasticache" else app.md
            request = json.loads(json.dumps(row["input"]).replace("<owner-redacted>", app.password))
            try:
                output = getattr(client, operation)(**request)
                code, status = "Success", output["ResponseMetadata"]["HTTPStatusCode"]
            except ClientError as error:
                output = error.response
                code, status = output["Error"]["Code"], output["ResponseMetadata"]["HTTPStatusCode"]
            if code != row["code"] or status != row["http_status"]:
                raise AssertionError(f"{filename}/{case}: local {code}/{status}, native {row['code']}/{row['http_status']}")
            if code == "Success":
                if operation in ("create_cache_parameter_group", "create_parameter_group"):
                    name = request.get("CacheParameterGroupName", request.get("ParameterGroupName"))
                    identity = (service, "parameters", name)
                    if identity not in owned:
                        owned.add(identity)
                        app.own(*identity)
                if operation == "create_user":
                    identity = (service, "user", request.get("UserId", request.get("UserName")))
                    if identity not in owned:
                        owned.add(identity)
                        app.own(*identity)
                expected = row.get("output", {})
                for field in ("CacheParameterGroup", "ParameterGroup", "User"):
                    if field in expected and field in output:
                        for key in ("CacheParameterGroupName", "ParameterGroupName", "Family", "CacheParameterGroupFamily", "Description", "Name", "Authentication"):
                            if key in expected[field] and output[field].get(key) != expected[field][key]:
                                raise AssertionError(f"{case}: meaningful {field}.{key} differs")
                if operation in ("describe_cache_parameters", "describe_parameters"):
                    parameter = next((v for v in expected.get("Parameters", []) if v.get("ParameterName", v.get("Name")) == "timeout"), None)
                    if parameter:
                        actual = next((v for v in output["Parameters"] if v.get("ParameterName", v.get("Name")) == "timeout"), None)
                        expected_value = parameter.get("ParameterValue", parameter.get("Value"))
                        actual_value = actual.get("ParameterValue", actual.get("Value")) if actual else None
                        if actual_value != expected_value:
                            raise AssertionError(f"{case}: native retained timeout value differs")
                if operation == "describe_users" and "Users" in expected:
                    expected_names = [v.get("Name", v.get("UserId")) for v in expected["Users"]]
                    actual_names = [v.get("Name", v.get("UserId")) for v in output["Users"]]
                    if actual_names != expected_names:
                        raise AssertionError(f"{case}: native user selection differs")
                for field in ("Users", "UserGroups"):
                    if expected.get(field) == [] and output.get(field) != []:
                        raise AssertionError(f"{case}: native empty {field} array omitted or changed")
            results.append({"fixture": filename, "case": case, "code": code, "http_status": status, "native_request_id": row["request_id"], "local_request_id": output["ResponseMetadata"]["RequestId"]})
    local = {}
    trails = app.client("cloudtrail")
    for source in ("elasticache.amazonaws.com", "memorydb.amazonaws.com"):
        request = {"LookupAttributes": [{"AttributeKey": "EventSource", "AttributeValue": source}], "MaxResults": 50}
        while True:
            response = trails.lookup_events(**request)
            for row in response["Events"]:
                event = json.loads(row["CloudTrailEvent"])
                local[event["requestID"]] = event
            if not response.get("NextToken"):
                break
            request["NextToken"] = response["NextToken"]
    audited = []
    for row in results:
        expected = expected_audit.get(row["native_request_id"])
        if not expected:
            continue
        actual = local.get(row["local_request_id"])
        if not actual:
            raise AssertionError(row["case"] + ": actual executable management record missing")
        for field in ("eventSource", "eventName", "readOnly", "eventCategory", "managementEvent"):
            if actual.get(field) != expected.get(field):
                raise AssertionError(row["case"] + ": native audit " + field + " differs")
        if (actual.get("responseElements") is None) != (expected.get("responseElements") is None):
            raise AssertionError(row["case"] + ": native audit response presence differs")
        if app.password in json.dumps(actual):
            raise AssertionError(row["case"] + ": secret leaked to management audit")
        audited.append({"case": row["case"], "eventSource": actual["eventSource"], "eventName": actual["eventName"], "readOnly": actual["readOnly"], "response_present": actual.get("responseElements") is not None})
    app.report["observations"]["native_management_replay"] = audited
