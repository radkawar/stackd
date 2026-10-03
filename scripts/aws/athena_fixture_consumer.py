#!/usr/bin/env python3
"""Assert actual Athena/S3 consumer contracts against bounded native fixtures.

PYTHONPATH=scripts/aws python3 -P scripts/aws/athena_fixture_consumer.py \
  --reference testdata/aws/athena/application_verified.json \
  --actual /tmp/stackd-application.json

Omit --actual to exercise native-fixture invariants only, not local conformance.
Use --kind cancellation for the separate immediate-stop native scenario. This
consumer makes no AWS calls and does not accept fabricated engine responses.
"""
import argparse
import csv
import io
import json

from glue_fixture_consumer import codes, load, observations, output


def application_contract(capture):
    rows = observations(capture)
    consumers = capture["consumers"]
    query_id = output(rows, "query-aggregate")["QueryExecutionId"]
    typed = output(rows, "typed-results")
    aggregate = output(rows, "aggregate-results")
    pages = [output(rows, label) for label in ("aggregate-results-page-one", "aggregate-results-page-2", "aggregate-results-page-3", "aggregate-results-page-4")]
    aggregate_rows = aggregate["ResultSet"]["Rows"]
    paged_rows = [row for page in pages for row in page["ResultSet"]["Rows"]]
    assert paged_rows == aggregate_rows, "Pagination must preserve header and every data row exactly once"
    assert aggregate_rows == [
        {"Data": [{"VarCharValue": "category"}, {"VarCharValue": "total"}]},
        {"Data": [{"VarCharValue": "north"}, {"VarCharValue": "10"}]},
        {"Data": [{"VarCharValue": "south"}, {"VarCharValue": "14"}]},
    ], "Actual S3 producer values must drive aggregate results"
    assert typed["ResultSet"]["Rows"][1]["Data"][0] == {}, "NULL must omit VarCharValue"
    assert typed["ResultSet"]["Rows"][1]["Data"][1] == {"VarCharValue": ""}, "Empty string is not NULL"
    csv_body = consumers["consume-query-csv"]["body_utf8"]
    assert list(csv.reader(io.StringIO(csv_body))) == [["category", "total"], ["north", "10"], ["south", "14"]]
    assert consumers["consume-produced-csv"]["body_utf8"] == "north,4\nsouth,14\nnorth,6\n"
    assert consumers["reader-s3-results-allowed"]["body_utf8"] == csv_body, "Athena API deny must not silently deny separately-authorized S3 bytes"
    assert capture["job_terminal"]["job-success"]["JobRunState"] == "SUCCEEDED"
    assert capture["job_terminal"]["job-failure"]["JobRunState"] == "FAILED"
    current = capture["query_terminal"]["aggregate"]
    location = current["ResultConfiguration"]["OutputLocation"]
    assert "/results/" in location and "/ignored-client/" not in location, "Enforced workgroup output must override client output"
    assert location.endswith(query_id + ".csv"), "Status output location must identify the consumed query result"
    assert capture["query_terminal"]["failure"]["Status"]["State"] == "FAILED"
    assert any(result["code"] == "AccessDenied" for label, result in rows.items() if label.startswith("reader-s3-denial-poll-")), "Changed current S3 policy must be observed"
    cancel_state = capture["query_terminal"]["cancel"]["Status"]["State"]
    assert cancel_state in ("SUCCEEDED", "CANCELLED"), "Application stop has a legitimate completion race"
    assert rows["cancelled-results"]["code"] == ("Success" if cancel_state == "SUCCEEDED" else "InvalidRequestException")
    error = capture["query_terminal"]["failure"]["Status"]["AthenaError"]
    old_prepared = output(rows, "get-prepared-after-duplicate")["PreparedStatement"]
    new_prepared = output(rows, "get-prepared-updated")["PreparedStatement"]
    removed = output(rows, "other-workgroup-after-remove")["WorkGroup"]["Configuration"]
    return {
        "codes": codes(rows, ("duplicate-workgroup", "catalog-missing-database", "catalog-missing-table", "query-missing-output", "query-token-mismatch", "failed-results", "duplicate-prepared", "update-prepared-missing", "get-prepared-other-workgroup", "reader-glue-table-denied", "reader-other-workgroup-denied", "reader-athena-results-denied", "reader-results-current-s3-deny", "query-disabled-workgroup", "get-results-disabled-workgroup", "delete-workgroup-nonrecursive")),
        "same_token_same_execution": {label: output(rows, label)["QueryExecutionId"] == query_id for label in ("query-idempotent-retry", "reader-idempotent-no-table-permission")},
        "aggregate": aggregate, "typed_results": typed,
        "page_continuations": ["NextToken" in page for page in pages],
        "page_rows": [page["ResultSet"]["Rows"] for page in pages],
        "query_csv_bytes": csv_body,
        "result_encryption": current["ResultConfiguration"].get("EncryptionConfiguration"),
        "failure_class": {key: error[key] for key in ("ErrorCategory", "ErrorType", "Retryable")},
        "other_workgroup_history": output(rows, "query-other-workgroup-history")["QueryExecutionIds"],
        "removed_result_configuration": removed.get("ResultConfiguration"),
        "prepared_old": {key: old_prepared.get(key) for key in ("QueryStatement", "Description")},
        "prepared_updated": {key: new_prepared.get(key) for key in ("QueryStatement", "Description")},
        "stop_job_errors": sorted(item["ErrorDetail"]["ErrorCode"] for item in output(rows, "stop-terminal-and-missing-runs")["Errors"]),
    }


def cancellation_contract(capture):
    rows = observations(capture)
    terminal = capture["terminal"]
    assert capture["cancellation_observed"] is True
    assert terminal["Status"]["State"] == "CANCELLED"
    assert rows["cancelled-results"]["code"] == "InvalidRequestException"
    return {"codes": codes(rows, ("stop-immediately", "stop-terminal-again", "cancelled-results")),
            "state": terminal["Status"]["State"],
            "statement_type": terminal["StatementType"],
            "substatement_type": terminal.get("SubstatementType")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("application", "cancellation"), default="application")
    parser.add_argument("--reference", required=True)
    parser.add_argument("--actual")
    args = parser.parse_args()
    contract = application_contract if args.kind == "application" else cancellation_contract
    expected = contract(load(args.reference))
    if args.actual:
        actual = contract(load(args.actual))
        if actual != expected:
            raise AssertionError(json.dumps({"expected": expected, "actual": actual}, indent=2))
        print(args.kind + ": native fixture comparison passed")
    else:
        print(json.dumps(expected, indent=2))
        print(args.kind + ": native consumer invariants passed (local replay not exercised)")


if __name__ == "__main__":
    main()
