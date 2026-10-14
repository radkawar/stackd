#!/usr/bin/env python3
"""Assert actual Athena/S3 consumer contracts against bounded native fixtures.

PYTHONPATH=scripts/aws python3 -P scripts/aws/athena_fixture_consumer.py \
  --reference testdata/aws/athena/application_verified.json \
  --actual /tmp/stackd-application.json

Omit --actual to exercise native-fixture invariants only, not local conformance.
Use --kind cancellation for the separate immediate-stop native scenario.
Use --kind manifest for the job-free CTAS/INSERT probe:
  PYTHONPATH=scripts/aws python3 -P scripts/aws/athena_application_probe.py \
    --manifest-only --endpoint-url http://127.0.0.1:4566 \
    --output .stackd/probes/athena-manifest-local.json
  PYTHONPATH=scripts/aws python3 -P scripts/aws/athena_fixture_consumer.py \
    --kind manifest --reference testdata/aws/athena/manifest_verified.json \
    --actual .stackd/probes/athena-manifest-local.json
This consumer makes no AWS calls and does not accept fabricated engine responses.
"""
import argparse
import csv
import io
import json
from urllib.parse import urlparse

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


def manifest_contract(capture):
    """Compare SDK/S3 observations, never runtime implementation text."""
    rows = observations(capture)
    assert capture["kind"] == "manifest"
    assert not any(row["service"] == "glue" and row["operation"] == "create-job"
                   for row in capture["observations"]), "Manifest-only mode must not create Glue jobs"
    bucket = capture["owned_resources"]["bucket"]

    def shape(result, manifest_body=None, recorded_offsets=None):
        if result["code"] != "Success":
            return {"code": result["code"],
                    "athena_error_code": result.get("error", {}).get("AthenaErrorCode")}
        value = result["output"]
        shaped = {"code": "Success", "columns": value["ResultSet"]["ResultSetMetadata"]["ColumnInfo"],
                  "rows": len(value["ResultSet"]["Rows"]), "update_count": value.get("UpdateCount"),
                  "update_count_present": "UpdateCount" in value,
                  "continuation": "NextToken" in value}
        if manifest_body is not None:
            shaped["body_byte_offsets"] = recorded_offsets if recorded_offsets is not None else [
                [manifest_body.encode().find(cell["VarCharValue"].encode())
                 if "VarCharValue" in cell else None for cell in row["Data"]]
                for row in value["ResultSet"]["Rows"]]
        return shaped

    writers = {}
    for label in ("ctas", "insert"):
        execution = capture["query_terminal"][label]
        assert execution["Status"]["State"] == "SUCCEEDED"
        location = execution["Statistics"]["DataManifestLocation"]
        parsed = urlparse(location)
        assert parsed.netloc == bucket and parsed.path.startswith("/results/")
        assert parsed.path.endswith(execution["QueryExecutionId"] + "-manifest.csv")
        consumer = capture["consumers"]["consume-" + label + "-manifest"]
        body = consumer["body_utf8"]
        assert len(body.encode("utf-8")) == consumer.get("normalized_byte_count", consumer["byte_count"])
        entries = list(csv.reader(io.StringIO(body)))
        assert entries and all(len(entry) == 1 for entry in entries)
        uris = [entry[0] for entry in entries]
        assert all(urlparse(uri).netloc == bucket and urlparse(uri).path.startswith("/data/written/")
                   for uri in uris), "Manifest entries must identify owned data writes"
        full = output(rows, label + "-manifest-full")
        result_rows = full["ResultSet"]["Rows"]
        values = [[cell.get("VarCharValue") for cell in row["Data"]] for row in result_rows]
        # Native header behavior is derived from the capture, not assigned.
        header = values[:-len(uris)] if len(values) >= len(uris) else []
        assert values[len(header):] == entries, "API manifest rows must preserve actual manifest object order"
        pages = [result["output"] for name, result in rows.items()
                 if name.startswith(label + "-manifest-page-") and result["code"] == "Success"]
        assert [row for page in pages for row in page["ResultSet"]["Rows"]] == result_rows
        assert all(page["ResultSet"]["ResultSetMetadata"] == full["ResultSet"]["ResultSetMetadata"]
                   and page.get("UpdateCount") == full.get("UpdateCount") for page in pages)
        assert pages and "NextToken" not in pages[-1]
        assert output(rows, label + "-rows-full").get("UpdateCount") == 2, "Each tiny writer must insert two actual rows"
        # File names and writer order are not a guaranteed cross-engine contract.
        # Their exact native bytes/order remain in the published capture; compare
        # partition identities and formatting while asserting API/S3 consistency.
        partitions = sorted(urlparse(uri).path.rsplit("/", 1)[0].split("/data/written/", 1)[1]
                            for uri in uris)
        quoted = sorted(line.startswith('"') and line.endswith('"') for line in body.splitlines())
        writers[label] = {
            "columns": full["ResultSet"]["ResultSetMetadata"]["ColumnInfo"],
            "header": header, "update_count": full.get("UpdateCount"),
            "update_count_present": "UpdateCount" in full,
            "continuation": "NextToken" in full,
            "partitions": partitions, "quoted_csv_records": quoted,
            "trailing_newline": body.endswith("\n"), "crlf": "\r\n" in body,
            "manifest_suffix": "-manifest.csv",
            "manifest_relative_parent": parsed.path.split("/results/", 1)[1].rpartition("/")[0],
            "output_has_csv_suffix": execution["ResultConfiguration"]["OutputLocation"].endswith(".csv"),
            "data_rows": output(rows, label + "-rows-full"),
            "pages": [{"count": len(page["ResultSet"]["Rows"]), "continuation": "NextToken" in page}
                      for page in pages],
            "boundaries": {str(limit): shape(rows[label + "-manifest-limit-" + str(limit)])
                           for limit in (2, 3)},
            "cross_tokens": {kind: shape(rows[label + "-" + kind],
                                          body if kind.endswith("as-manifest") else None,
                                          capture.get("manifest_body_byte_offsets", {}).get(label + "-" + kind)) for kind in
                             ("manifest-token-as-rows", "rows-token-as-manifest",
                              "select-rows-token-as-manifest", "select-rows-token-as-rows")
                             if label + "-" + kind in rows},
            "row_pages": {str(index): shape(rows[label + "-rows-page-" + str(index)])
                          for index in (1, 2) if label + "-rows-page-" + str(index) in rows},
        }
    assert capture["query_terminal"]["failed"]["Status"]["State"] == "FAILED"
    assert any(result["code"] == "AccessDenied" for name, result in rows.items()
               if name.startswith("reader-manifest-deny-poll-"))
    return {
        "writers": writers,
        "selected": output(rows, "select-rows"),
        "manifest_errors": {label: {
            "code": rows[label]["code"], "athena_error_code": rows[label].get("error", {}).get("AthenaErrorCode")}
            for label in ("select-manifest", "failed-manifest", "failed-rows",
                          "reader-manifest-current-s3-deny", "select-rows-token-as-manifest")},
        "reader_allowed": shape(rows["reader-manifest-allowed"]),
        "statement_types": {name: {"statement": value["StatementType"],
                                   "substatement": value.get("SubstatementType"),
                                   "manifest_present": "DataManifestLocation" in value.get("Statistics", {})}
                            for name, value in capture["query_terminal"].items()},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("application", "cancellation", "manifest"), default="application")
    parser.add_argument("--reference", required=True)
    parser.add_argument("--actual")
    args = parser.parse_args()
    contract = {"application": application_contract, "cancellation": cancellation_contract,
                "manifest": manifest_contract}[args.kind]
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
