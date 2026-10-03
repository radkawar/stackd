#!/usr/bin/env python3
"""Capture native Logs filter language and cross-check an owned published corpus.

Run with python3 -B scripts/aws/logs_filters_probe.py --account ACCOUNT. No persistent filters,
metrics, roles, or policies are created. Only a fresh log group/stream is owned.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import time
import uuid

from aws_cli import ProbeResult, observe


# Strings are the original event payloads: do not parse/reserialize the JSON cases.
CORPORA = {
    "terms": [
        "ERROR ARGUMENTS REQUEST", "ERROR BAD REQUEST", "INFO ARGUMENTS",
        "INFO REQUEST", "error arguments request", "ERROR INTERNAL SERVER ERROR",
        "ERROR INTERNAL  SERVER ERROR", "INTERNAL SERVER error", "TERROR REQUEST",
        "[ERROR] REQUEST", "ERROR-REQUEST", "ERROR_ARGUMENTS", "ERROR\nARGUMENTS",
        "ARGUMENTS ERROR", "plain", 'say "hello world" now', "hello-world", " ",
    ],
    "regex": [
        "ERROR 500", "ERROR 50", "ERROR 5000", "WARN 404", "xERROR 500",
        "error 500", "color", "colour", "colouur", "10.10.0.1", "10010,051",
        "hello!", "hello(", "café", "aaab", "abab", "ERROR\n500",
    ],
    "scalars": [
        '{}', '{"v":null}', '{"v":"null"}', '{"v":true}', '{"v":false}',
        '{"v":"true"}', '{"v":"false"}', '{"v":0}', '{"v":1}', '{"v":1.0}',
        '{"v":1e0}', '{"v":"1"}', '{"v":"1.0"}', '{"v":-1}', '{"v":1.5}',
        '{"v":10}', '{"v":"10"}', '{"v":"Alpha"}', '{"v":"alpha"}',
        '{"v":"Alphabet"}', '{"v":"xAlpha"}', '{"v":""}', '{"v":[]}',
        '{"v":{}}', '{"v":[1,"Alpha",null]}', '{"v":"a*b"}', '{"v":"a?b"}',
        '{"v":1,"v":2}', '{"v":2,"v":1}', 'not JSON', '[{"v":1}]', '{broken',
    ],
    "paths": [
        '{"nested":{"value":"hit"},"cluster.name":"flat","cluster":{"name":"nested"},"items":[{"a":1,"b":0},{"a":0,"b":2}],"arr":["miss","hit"],"matrix":[[0,1],[2,3]],"a":1,"b":0,"c":0}',
        '{"nested":{"value":"miss"},"cluster.name":"nested","cluster":{"name":"flat"},"items":[{"a":1,"b":2}],"arr":["hit","miss"],"matrix":[[1,0]],"a":0,"b":2,"c":3}',
        '{"nested":null,"arr":[null],"items":[],"a":0,"b":2,"c":0}',
        '{"nested":{},"arr":[],"a":1,"b":2,"c":3}',
        '{"nested":{"value":null},"arr":"hit","a":0,"b":0,"c":3}',
        '{"nested":{"value":"null"},"other":"hit"}',
        '{"nested.value":"hit","arr":[["hit"]]}',
        '{"arr":["hit","hit"],"items":[{"a":1},{"b":2}]}',
        '{"arr":{"0":"hit"},"nested":[{"value":"hit"}]}', '{}',
    ],
    "space": [
        '127.0.0.1 - frank [10/Oct/2000:13:25:15 -0700] "GET /index.html HTTP/1.0" 404 1534',
        '127.0.0.2 - jane [10/Oct/2000:13:25:16 -0700] "GET /index.html HTTP/1.0" 410 0',
        '127.0.0.3 - frank [10/Oct/2000:13:25:17 -0700] "POST /api HTTP/1.0" 500 2048',
        '127.0.0.4 - frank [10/Oct/2000:13:25:18 -0700] "GET /index.html HTTP/1.0" 200 100',
        '127.0.0.5  -  frank [10/Oct/2000:13:25:19 -0700] "GET /index.html HTTP/1.0" 404 1534 extra',
        '127.0.0.6\t-\tfrank\t[10/Oct/2000:13:25:20 -0700]\t"GET /index.html HTTP/1.0"\t404\t1534',
        'ERROR request failed', 'WARNING request', 'INFO request accepted',
        'ERROR', 'ERROR "two words"', 'ERROR "unterminated words',
    ],
}

# label, original corpus, native pattern, cross-check FilterLogEvents as well.
CASES = [
    ("empty", "terms", "", True),
    ("quoted_space", "terms", '" "', False),
    ("required_term", "terms", "ERROR", True),
    ("required_terms", "terms", "ERROR ARGUMENTS", True),
    ("optional_terms", "terms", "?ERROR ?ARGUMENTS", True),
    ("optional_with_required", "terms", "?ERROR ?ARGUMENTS REQUEST", True),
    ("optional_with_excluded", "terms", "?ERROR ?ARGUMENTS -REQUEST", True),
    ("include_exclude", "terms", "ERROR -ARGUMENTS", True),
    ("exclude_only", "terms", "-ERROR", False),
    ("exact_phrase", "terms", '"INTERNAL SERVER ERROR"', True),
    ("lowercase", "terms", "error", False),
    ("quoted_punctuation", "terms", '"hello-world"', False),
    ("exclude_phrase", "terms", 'ERROR -"BAD REQUEST"', False),
    ("term_wildcard", "terms", "ERR*", False),
    ("regex_anchor_class_repeat", "regex", "%^ERROR\\s[0-9]{3}$%", True),
    ("regex_alternation", "regex", "%ERROR|WARN%", True),
    ("regex_optional", "regex", "%^colou?r$%", False),
    ("regex_escaped_dots", "regex", r"%10\.10\.0\.1%", True),
    ("regex_unescaped_dots", "regex", "%10.10.0.1%", False),
    ("regex_hex_symbol", "regex", r"%\x21%", False),
    ("regex_plus_negated_class", "regex", "%^[^a-z]+$%", False),
    ("regex_star", "regex", "%^a*b$%", False),
    ("regex_group_rejected", "regex", "%^(ERROR|WARN)%", True),
    ("regex_symbol_rejected", "regex", "%hello!%", True),
    ("regex_multibyte", "regex", "%café%", True),
    ("regex_lookahead_rejected", "regex", "%ERROR(?= 500)%", False),
    ("regex_unclosed_class", "regex", "%[abc%", False),
    ("json_number_equal", "scalars", "{ $.v = 1 }", True),
    ("json_number_unequal", "scalars", "{ $.v != 1 }", True),
    ("json_number_greater", "scalars", "{ $.v > 1 }", True),
    ("json_number_less", "scalars", "{ $.v < 1 }", False),
    ("json_number_greater_equal", "scalars", "{ $.v >= 1 }", False),
    ("json_number_less_equal", "scalars", "{ $.v <= 1 }", False),
    ("json_number_exponent", "scalars", "{ $.v = 1e+0 }", False),
    ("json_number_negative", "scalars", "{ $.v = -1 }", False),
    ("json_quoted_number", "scalars", '{ $.v = "1" }', True),
    ("json_string_equal", "scalars", '{ $.v = "Alpha" }', True),
    ("json_string_unequal", "scalars", '{ $.v != "Alpha" }', False),
    ("json_string_prefix", "scalars", '{ $.v = "Alpha*" }', True),
    ("json_string_suffix", "scalars", '{ $.v = "*Alpha" }', False),
    ("json_string_question", "scalars", '{ $.v = "a?b" }', False),
    ("json_string_empty", "scalars", '{ $.v = "" }', False),
    ("json_string_regex", "scalars", "{ $.v = %^Al.*% }", True),
    ("json_is_null", "scalars", "{ $.v IS NULL }", True),
    ("json_not_exists", "scalars", "{ $.v NOT EXISTS }", True),
    ("json_is_true", "scalars", "{ $.v IS TRUE }", True),
    ("json_is_false", "scalars", "{ $.v IS FALSE }", False),
    ("json_equal_true", "scalars", "{ $.v = true }", False),
    ("json_equal_null", "scalars", "{ $.v = null }", False),
    ("json_any_value", "scalars", "{ $.v = * }", False),
    ("json_nested", "paths", '{ $.nested.value = "hit" }', True),
    ("json_dotted_key", "paths", '{ $.[\'cluster.name\'] = "flat" }', True),
    ("json_dotted_traversal", "paths", '{ $.cluster.name = "flat" }', False),
    ("json_array_index", "paths", '{ $.arr[0] = "hit" }', True),
    ("json_array_wildcard", "paths", '{ $.arr[*] = "hit" }', True),
    ("json_object_wildcard", "paths", '{ $.* = "hit" }', True),
    ("json_matrix_index", "paths", "{ $.matrix[0][1] = 1 }", False),
    ("json_wildcard_cross_element_and", "paths", "{ $.items[*].a = 1 && $.items[*].b = 2 }", True),
    ("json_and", "paths", "{ $.a = 1 && $.c = 3 }", False),
    ("json_or_precedence", "paths", "{ $.a = 1 || $.b = 2 && $.c = 3 }", True),
    ("json_grouped_precedence", "paths", "{ ($.a = 1 || $.b = 2) && $.c = 3 }", True),
    ("json_nested_missing", "paths", "{ $.nested.value NOT EXISTS }", False),
    ("json_nested_null", "paths", "{ $.nested.value IS NULL }", False),
    ("space_extract", "space", "[ip, identity, user, timestamp, request, status, bytes]", True),
    ("space_numeric", "space", "[ip, identity, user, timestamp, request, status >= 400, bytes > 1000]", True),
    ("space_wildcard", "space", "[..., request = *.html*, status = 4*, bytes]", True),
    ("space_or", "space", "[..., status = 404 || status = 410, bytes]", True),
    ("space_regex", "space", r"[ip = %127\.0\.0\.[1-3]%, identity, user, timestamp, request, status, bytes]", False),
    ("space_ellipsis_suffix", "space", "[..., bytes]", False),
    ("space_ellipsis_middle", "space", "[ip, ..., status, bytes]", False),
    ("space_anonymous", "space", "[]", False),
    ("space_ordered_term", "space", "[w1=ERROR, w2]", True),
    ("space_exclude_terms", "space", "[w1!=ERROR && w1!=WARNING, w2]", False),
    ("invalid_json_exists", "scalars", "{ $.v EXISTS }", True),
    ("invalid_json_is_not", "scalars", "{ $.v IS NOT NULL }", True),
    ("invalid_json_double_equal", "scalars", "{ $.v == 1 }", True),
    ("invalid_json_not_operator", "scalars", "{ !($.v = 1) }", False),
    ("invalid_json_textual_and", "scalars", "{ $.v > 0 AND $.v < 2 }", False),
    ("invalid_json_eventbridge_pattern", "scalars", '{ "v": [1] }', True),
    ("invalid_json_string_order", "scalars", '{ $.v > "Alpha" }', False),
    ("invalid_json_regex_groups", "scalars", "{ $.v = %(Alpha|Beta)% }", False),
    ("invalid_json_multiple_path_wildcards", "paths", "{ $.items[*].* = 1 }", True),
    ("invalid_json_recursive_descent", "paths", '{ $..value = "hit" }', False),
    ("invalid_json_negative_index", "paths", '{ $.arr[-1] = "hit" }', False),
    ("invalid_json_slice", "paths", '{ $.arr[0:2] = "hit" }', False),
    ("invalid_json_four_wildcards", "paths", '{ $.arr[*] = "hit" || $.items[*].a = 1 || $.* = "hit" || $.matrix[*][0] = 0 }', False),
    ("invalid_json_three_regex", "scalars", "{ $.v = %Alpha% || $.v = %Beta% || $.v = %Gamma% }", True),
    ("invalid_space_multiple_ellipsis", "space", "[..., status, ...]", True),
    ("invalid_space_duplicate_name", "space", "[word, word]", False),
    ("invalid_unclosed_quote", "terms", '"ERROR', True),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    args = parser.parse_args()
    region = "us-east-1"
    env = dict(os.environ, AWS_DEFAULT_REGION=region, AWS_REGION=region,
               AWS_MAX_ATTEMPTS="1", AWS_PAGER="")
    identity = observe("sts", "get-caller-identity", {}, env, paginate=False)
    if identity["code"] != "Success" or identity["output"]["Account"] != args.account:
        raise RuntimeError("Caller identity did not satisfy the owned-account guard")
    caller = identity["output"]
    substitutions = [(caller["Arn"], "arn:aws:iam::111111111111:user/PROBE_CALLER"),
                     (caller["UserId"], "PROBE_CALLER_ID"), (caller["Account"], "111111111111")]
    group = "/stackd/probe/logs-filters-" + uuid.uuid4().hex
    stream = "language-corpus"
    now = int(time.time() * 1000) - 1000
    events = []
    indices = {}
    for corpus, messages in CORPORA.items():
        indices[corpus] = list(range(len(events), len(events) + len(messages)))
        events.extend([{"timestamp": now + (len(events) + i) * 10, "message": message}
                       for i, message in enumerate(messages)])
    fixture = {
        "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "region": region,
        "scope": "Native TestMetricFilter language oracle (outside the pinned 57-operation target), with representative FilterLogEvents queries over one owned published corpus; not full Logs parity.",
        "primary_references": [
            "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html",
            "https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_FilterLogEvents.html",
            "https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_TestMetricFilter.html",
        ],
        "identity_relationships": {
            "caller_account": "111111111111", "resource_owner": "caller_account",
            "substitutions": "Exact caller ARN, UserId and account replaced consistently with synthetic caller ARN, PROBE_CALLER_ID and 111111111111. Synthetic ARN does not assert the native caller principal kind. No credentials captured. Owned names, native timestamps, event IDs, opaque tokens, nulls, field presence and response ordering are unchanged.",
        },
        "corpus": [{"original_event_index": index, **event} for index, event in enumerate(events)],
        "corpus_indices": indices,
        "index_semantics": "Native TestMetricFilter eventNumber is retained verbatim (the initial empty-pattern probe returned 1 through 18, unlike the API examples' zero-based indices). original_event_indices is zero-based and resolves each unique original eventMessage within its input corpus, independently of eventNumber. FilterLogEvents indices resolve timestamp/message pairs to that same corpus. ProbeResult objects are unchanged apart from documented identity substitutions; extractedValues preserves native values without coercing their types.",
        "observations": [], "comparisons": [],
        "visibility": {"max_attempts": 20, "interval_seconds": 2, "max_pages_per_query": 8},
        "cleanup": {"verified": False, "observations": []},
    }
    destination = Path(__file__).resolve().parents[2] / ".stackd/probes/logs/filters.json"

    def redact(value):
        if isinstance(value, str):
            for source, target in substitutions:
                value = value.replace(source, target)
            return value
        if isinstance(value, list):
            return [redact(item) for item in value]
        if isinstance(value, dict):
            return {redact(key): redact(item) for key, item in value.items()}
        return value

    def capture(label, operation, parameters, *, cleanup=False):
        result: ProbeResult = observe("logs", operation, parameters, env, paginate=False)
        row = {"label": label, "service": "logs", "operation": operation,
               "input": parameters, "result": result}
        (fixture["cleanup"]["observations"] if cleanup else fixture["observations"]).append(row)
        return row

    def require(row):
        if row["result"]["code"] != "Success":
            raise RuntimeError("Required operation failed: " + row["label"] + ": " + row["result"]["code"])
        return row["result"].get("output", {})

    event_indices = {(event["timestamp"], event["message"]): index for index, event in enumerate(events)}

    def query(label, parameters):
        matched = []
        pages = []
        seen_tokens = set()
        for page in range(fixture["visibility"]["max_pages_per_query"]):
            row = capture(f"{label}.page_{page}", "filter-log-events", parameters)
            pages.append(row["label"])
            if row["result"]["code"] != "Success":
                return row["result"]["code"], matched, pages
            output = row["result"]["output"]
            row["original_event_indices"] = [event_indices[(event["timestamp"], event["message"])]
                                               for event in output.get("events", [])]
            matched.extend(row["original_event_indices"])
            token = output.get("nextToken")
            if token is None:
                return "Success", matched, pages
            if token in seen_tokens:
                raise RuntimeError("FilterLogEvents repeated a pagination token")
            seen_tokens.add(token)
            parameters = dict(parameters, nextToken=token)
        raise RuntimeError("FilterLogEvents exceeded bounded pagination")

    created = False
    try:
        require(capture("create_owned_group", "create-log-group", {"logGroupName": group}))
        created = True
        require(capture("create_owned_stream", "create-log-stream", {"logGroupName": group, "logStreamName": stream}))
        require(capture("publish_corpus", "put-log-events", {"logGroupName": group, "logStreamName": stream, "logEvents": events}))
        base = {"logGroupName": group, "logStreamNames": [stream], "startTime": now,
                "endTime": events[-1]["timestamp"] + 1, "limit": 1000}
        for attempt in range(fixture["visibility"]["max_attempts"]):
            code, matched, _ = query(f"visibility_{attempt}", base)
            if code != "Success":
                raise RuntimeError("Visibility query failed: " + code)
            if matched == list(range(len(events))):
                fixture["visibility"]["visible_attempt"] = attempt
                fixture["visibility"]["complete_corpus_visible"] = True
                break
            if attempt + 1 < fixture["visibility"]["max_attempts"]:
                time.sleep(fixture["visibility"]["interval_seconds"])
        else:
            raise RuntimeError("Published corpus did not become fully visible within bounded wait")
        for label, corpus, pattern, published in CASES:
            row = capture(label, "test-metric-filter", {"filterPattern": pattern, "logEventMessages": CORPORA[corpus]})
            row["corpus"] = corpus
            oracle = row["result"]
            if oracle["code"] == "Success":
                by_message = dict(zip(CORPORA[corpus], indices[corpus]))
                row["original_event_indices"] = [by_message[match["eventMessage"]]
                                                 for match in oracle["output"].get("matches", [])]
            if published:
                # Ten-millisecond spacing avoids dependence on endTime inclusivity.
                parameters = dict(base, filterPattern=pattern, startTime=now + indices[corpus][0] * 10,
                                  endTime=now + indices[corpus][-1] * 10 + 1)
                code, matched, pages = query("published_" + label, parameters)
                fixture["comparisons"].append({
                    "oracle_label": label, "filter_log_events_labels": pages,
                    "oracle_code": oracle["code"], "filter_log_events_code": code,
                    "oracle_original_event_indices": row.get("original_event_indices"),
                    "filter_log_events_original_event_indices": matched if code == "Success" else None,
                    "same_code": oracle["code"] == code,
                    "same_matches": row["original_event_indices"] == matched if oracle["code"] == code == "Success" else None,
                })
            print(label + ": " + oracle["code"], flush=True)
    finally:
        try:
            if created:
                require(capture("delete_owned_group", "delete-log-group", {"logGroupName": group}, cleanup=True))
                check = capture("verify_group_and_stream_absent", "describe-log-streams",
                                {"logGroupName": group, "logStreamNamePrefix": stream}, cleanup=True)
                fixture["cleanup"]["verified"] = check["result"]["code"] == "ResourceNotFoundException"
                if not fixture["cleanup"]["verified"]:
                    raise RuntimeError("Owned group deletion was not verified")
        finally:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(json.dumps(redact(fixture), indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"cases": len(CASES), "comparisons": len(fixture["comparisons"]),
                      "cleanup_verified": fixture["cleanup"]["verified"]}), flush=True)


if __name__ == "__main__":
    main()
