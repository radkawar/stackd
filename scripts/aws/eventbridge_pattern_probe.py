#!/usr/bin/env python3
"""Read-only EventBridge TestEventPattern observations; creates no resources."""
import argparse
import concurrent.futures
import datetime
import json
import os
from pathlib import Path

from aws_cli import observe, require_account


def cases():
    rows = []

    def add(name, pattern, detail):
        if not isinstance(pattern, str):
            pattern = json.dumps(pattern, separators=(",", ":"))
        event = {"version": "0", "id": "00000000-0000-4000-8000-000000000001",
                 "detail-type": "probe", "source": "stackd.pattern.probe",
                 "account": "111111111111", "time": "2026-09-13T00:00:00Z",
                 "region": "us-east-1", "resources": []}
        raw = detail if isinstance(detail, str) else json.dumps(detail, separators=(",", ":"))
        rows.append({"case": name, "pattern": pattern,
                     "event": json.dumps(event, separators=(",", ":"))[:-1] + ',"detail":' + raw + "}"})

    for scalar in [1, "1", True, "true", None, "null"]:
        for value in [1, "1", True, "true", None, "null"]:
            add("scalar_" + json.dumps(scalar) + "_" + json.dumps(value), {"detail": {"v": [scalar]}}, {"v": value})
    for number in ["1", "1.0", "1e0", "-0", "0", "9007199254740992", "9007199254740993"]:
        add("number_lexeme_" + number, '{"detail":{"v":[1]}}', '{"v":' + number + '}')
    for value in [{}, {"v": None}, {"v": {}}, {"v": []}, {"v": [None]}, {"v": [{"x": 1}]}, {"v": [[], {}]}]:
        for exists in [True, False]:
            add("exists_" + str(exists) + "_" + json.dumps(value), {"detail": {"v": [{"exists": exists}]}}, value)
    for value in [[], ["a"], ["b", "a"], [["a"]], [["a", "b"]], [{"v": "a"}]]:
        add("array_" + json.dumps(value), {"detail": {"v": ["a"]}}, {"v": value})
    for value in [[{"a": 1, "b": 2}], [{"a": 1}, {"b": 2}], [{"a": 1, "b": 0}, {"a": 0, "b": 2}], [{"a": 1}, {"a": 0, "b": 2}]]:
        add("correlated_" + json.dumps(value), {"detail": {"v": {"a": [1], "b": [2]}}}, {"v": value})
        add("correlated_absent_" + json.dumps(value), {"detail": {"v": {"a": [1], "b": [{"exists": False}]}}}, {"v": value})
    operators = [
        {"prefix": "ab"}, {"suffix": "yz"}, {"equals-ignore-case": "AbC"},
        {"prefix": {"equals-ignore-case": "Ab"}}, {"suffix": {"equals-ignore-case": "Yz"}},
        {"anything-but": "abc"}, {"anything-but": ["abc", "xyz"]}, {"anything-but": 1},
        {"anything-but": {"prefix": ["a", "b"]}}, {"anything-but": {"suffix": ["a", "b"]}},
        {"anything-but": {"equals-ignore-case": ["ABC", "XYZ"]}},
        {"wildcard": "a*b?c"}, {"wildcard": "a\\*b"}, {"wildcard": "a\\\\b"},
        {"anything-but": {"wildcard": ["a*b", "x*y"]}},
        {"numeric": [">", 0, "<=", 2]}, {"cidr": "10.0.0.0/24"}, {"cidr": "2001:db8::/32"},
    ]
    for index, operator in enumerate(operators):
        for value in ["abc", "AbC", "ab?c", "a*b", "a\\b", "xyz", "10.0.0.2", "2001:db8::1", 1, "1", True, None]:
            add(f"operator_{index}_{json.dumps(value)}", {"detail": {"v": [operator]}}, {"v": value})
    malformed = [[], None, {"detail": {}}, {"detail": {"v": []}}, {"detail": {"v": [[1]]}},
        {"detail": {"v": [{"prefix": 1}]}}, {"detail": {"v": [{"prefix": ["a"]}]}},
        {"detail": {"v": [{"prefix": "a", "suffix": "z"}]}}, {"detail": {"v": [{}]}},
        {"detail": {"v": [{"unknown": "x"}]}}, {"detail": {"v": [{"exists": 1}]}},
        {"detail": {"v": [{"anything-but": []}]}}, {"detail": {"v": [{"anything-but": [1, "a"]}]}},
        {"detail": {"v": [{"anything-but": True}]}}, {"detail": {"v": [{"anything-but": None}]}},
        {"detail": {"v": [{"anything-but": {"prefix": []}}]}},
        {"detail": {"v": [{"anything-but": {"prefix": ""}}]}},
        {"detail": {"v": [{"prefix": {"equals-ignore-case": ["a"]}}]}},
        {"detail": {"v": [{"wildcard": "a**b"}]}}, {"detail": {"v": [{"wildcard": "a\\qb"}]}},
        {"detail": {"v": [{"wildcard": "a\\"}]}}, {"detail": {"v": [{"cidr": "10.0.0.1/24"}]}},
        {"detail": {"v": [{"cidr": "10.0.0.1"}]}},
        {"$or": []}, {"$or": [{"source": ["a"]}]}, {"$or": [1, 2]},
        {"$or": [{"source": ["a"]}, {}]}, {"$or": [{"prefix": ["a"]}, {"source": ["b"]}]},
    ]
    for index, pattern in enumerate(malformed):
        add(f"validation_{index}", pattern, {"v": "abc"})
    for index, values in enumerate([[], ["=", 1], ["=", 1, "<", 3], [">", 0, ">", 1], [">", 3, "<", 1], ["!=", 1], [">", "1"], [">", 5000000001], ["=", 0.1234567], ["=", 1e100], ["<", 2, ">", 0], [">=", 1, "<=", 1]]):
        add(f"numeric_validation_{index}", {"detail": {"v": [{"numeric": values}]}}, {"v": 1})
    for pattern in [{}, {"detail": {"v": [{"exists": False}, "a"]}},
                    {"detail": {"$or": [{"a": [1]}, {"b": [2]}], "c": [3]}},
                    {"detail": {"a": [0], "$or": [{"a": [1]}, {"b": [2]}]}},
                    {"detail": {"$or": [{"a": [1]}, {"b": [2]}], "a": [0]}}]:
        for detail in [{}, {"v": "a"}, {"a": 1, "c": 3}, {"a": 0, "b": 2, "c": 3}]:
            add("logic_" + json.dumps(pattern) + "_" + json.dumps(detail), pattern, detail)
    for pattern in ['{"detail":{"a.b":[1]}}', '{"detail.a":{"b":[1]}}',
                    '{"detail":{"a.b":[1],"a":{"b":[2]}}}',
                    '{"detail":{"a":{"b":[2]},"a.b":[1]}}',
                    '{"detail":{"v":[0],"v":[1]}}']:
        for detail in ['{"a":{"b":1},"v":1}', '{"a.b":1,"v":0}', '{"a":{"b":2}}']:
            add("dots_duplicates_" + pattern + "_" + detail, pattern, detail)

    for number in ["9007199254740992", "9007199254740993", "1.0000000000000001", "1e100", "1e309", "1e-400", "-0", "0.1234567890123456789"]:
        for op in ["literal", "numeric"]:
            expression = number if op == "literal" else '{"numeric":["=",' + number + ']}'
            for event in [number, "1", "0", "9007199254740992"]:
                add(f"edge_precision_{op}_{number}_{event}", '{"detail":{"v":[' + expression + ']}}', '{"v":' + event + '}')
    for detail in [{"v": [{"a": 1}, {"b": 2}]}, {"v": [[], [{"a": 1}]]}, {"v": [1, {"a": 1}]}, {"v": [{"a": 1, "b": 0}, {"a": 1, "b": 2}]}, {"v": [{"a": 1}, {}]}, {"v": []}]:
        for pattern in [{"detail": {"v": {"a": [{"exists": False}], "b": [{"exists": False}]}}},
                        {"detail": {"v": {"b": [{"exists": False}], "a": [1]}}},
                        {"detail": {"v": {"a": [{"exists": False}]}}}]:
            add("edge_absence_" + json.dumps(pattern) + "_" + json.dumps(detail), pattern, detail)
    for pattern in ['{"detail":{"v":null,"v":[1]}}', '{"detail":{"v":[1],"v":null}}',
                    '{"detail":{"a":{},"a":{"b":[1]}}}', '{"detail":{"v":[0],"v":[1]}}',
                    '{"detail":{"v":[{"prefix":"a","prefix":"b"}]}}',
                    '{"detail":{"":{"v":[1]}}}', '{"":{"v":[1]}}']:
        for detail in ['{"v":0,"v":1}', '{"v":1,"v":0}', '{"":{"v":1}}']:
            add("edge_duplicates_" + pattern + "_" + detail, pattern, detail)
    add("edge_duplicate_objects", '{"detail":{"a":{"x":[1]},"a":{"y":[2]}}}', {"a": {"y": 2}})
    add("edge_duplicate_objects_both", '{"detail":{"a":{"x":[1]},"a":{"y":[2]}}}', {"a": {"x": 1, "y": 2}})
    add("edge_duplicate_event_zero", '{"detail":{"v":[0]}}', '{"v":0,"v":1}')
    add("edge_duplicate_event_one", '{"detail":{"v":[1]}}', '{"v":0,"v":1}')
    for operator in ["prefix", "suffix", "numeric", "exists", "cidr", "wildcard", "equals-ignore-case", "anything-but", "exactly", "$or"]:
        add("edge_or_reserved_" + operator, {"detail": {"$or": [{"nested": {operator: ["x"]}}, {"v": ["x"]}]}}, {"v": "x"})
    for number in ["9007199254740993", "1.0000000000000001", "1e309", "1e-400"]:
        add("edge_negated_number_" + number, '{"detail":{"v":[{"anything-but":' + number + '}]}}', {"v": 1})
    for network in ["010.0.0.0/8", "10.0.0.1/0", "2001:db8::/0", "::ffff:192.0.2.0/120"]:
        add("edge_cidr_" + network, {"detail": {"v": [{"cidr": network}]}}, {"v": 1})
    for exponent in [9, 10]:
        add(f"edge_or_combinations_{2**exponent}", {"detail": {f"g{i}": {"$or": [{"v": [1]}, {"v": [2]}]} for i in range(exponent)}}, {})
    for operator in [{"anything-but": {"prefix": []}}, {"anything-but": {"suffix": []}}, {"anything-but": {"wildcard": []}}, {"anything-but": {"equals-ignore-case": []}}, {"equals-ignore-case": "K"}, {"equals-ignore-case": "S"}]:
        for value in ["K", "ſ", "x"]:
            add("edge_string_" + json.dumps(operator) + "_" + value, {"detail": {"v": [operator]}}, {"v": value})
    for value in [["a", "b"], ["a"], [["a"], ["b"]], []]:
        add("edge_anything_but_array_" + json.dumps(value), {"detail": {"v": [{"anything-but": "a"}]}}, {"v": value})

    for network, value in [("10.0.0.0/8", "a00::1"), ("::/0", "10.0.0.1"),
                           ("0.0.0.0/0", "2001:db8::1"), ("10.0.0.1/32", "10.0.0.1"),
                           ("2001:db8::1/128", "2001:db8::1"), ("10.0.0.1/31", "10.0.0.1"),
                           ("2001:db8::1/127", "2001:db8::1")]:
        add(f"edge_depth_cidr_{network}_{value}", {"detail": {"v": [{"cidr": network}]}}, {"v": value})
    for pattern, value in [("ß", "ß"), ("ß", "SS"), ("ß", "ss"), ("ß", "Ss"), ("ﬀ", "FF"),
                           ("İ", "i"), ("İ", "i\u0307"), ("İ", "İ"), ("ΐ", "Ι\u0308\u0301"),
                           ("Straße", "STRASSE"), ("😀", "😀"), ("𐐀", "𐐀"), ("𐐀", "𐐨"),
                           ("😀", "??"), ("😀", "?"), ("𐐀", "??")]:
        add(f"edge_depth_casefold_{pattern}_{value}", {"detail": {"v": [{"equals-ignore-case": pattern}]}}, {"v": value})
    for operator, pattern, value in [("prefix", "ß", "SSabc"), ("prefix", "ß", "ssabc"),
                                     ("suffix", "ß", "abcSS"), ("suffix", "ß", "abcss"),
                                     ("prefix", "İ", "i\u0307abc"), ("suffix", "İ", "abci\u0307")]:
        add(f"edge_depth_{operator}_{pattern}_{value}", {"detail": {"v": [{operator: {"equals-ignore-case": pattern}}]}}, {"v": value})
    for pattern, value in [("ß", "SS"), ("İ", "i"), ("İ", "i\u0307"), ("😀", "😀")]:
        add(f"edge_depth_notcasefold_{pattern}_{value}", {"detail": {"v": [{"anything-but": {"equals-ignore-case": pattern}}]}}, {"v": value})
    array_pattern = {f"tags{i}": [{"prefix": "x"}] for i in range(8)}
    array_detail = {f"tags{i}": [f"x{j}" for j in range(5)] for i in range(8)}
    for name, status in [("miss", "other"), ("match", "ready")]:
        add(f"edge_depth_arrays_independent_terminal_{name}",
            {"detail": dict(array_pattern, status=["ready"])}, dict(array_detail, status=status))
    add("edge_depth_arrays_independent_correlation_conflict",
        {"detail": dict(array_pattern, status=["ready"], resources={"region": [{"prefix": "x"}], "state": ["ready"]})},
        dict(array_detail, status="ready", resources=[{"region": "x0", "state": "other"}, {"region": "y", "state": "ready"}]))

    template = json.loads(rows[0]["event"])
    events = [("detail_only", {"detail": {"v": 1}}), ("empty", {}), ("array", []), ("scalar", 1)]
    events += [("missing_" + field, {key: value for key, value in template.items() if key != field}) for field in template]
    events += [("type_" + field, dict(template, **{field: 1})) for field in template]
    events += [("bad_time", dict(template, time="not-a-time")), ("null_detail", dict(template, detail=None))]
    for name, event in events:
        rows.append({"case": "edge_envelope_" + name, "pattern": '{"source":["stackd.pattern.probe"]}', "event": json.dumps(event)})
    rows.append({"case": "edge_envelope_malformed", "pattern": '{"source":["stackd.pattern.probe"]}', "event": "{"})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--edges", action="store_true")
    args = parser.parse_args()
    fixture = {"source": "Read-only native AWS EventBridge TestEventPattern", "region": "us-east-1",
               "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "documentation": ["https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-pattern-operators.html",
                                 "https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-pattern.html"],
               "observations": [], "cleanup": "No resources created or changed."}
    env = dict(os.environ, AWS_DEFAULT_REGION="us-east-1", AWS_MAX_ATTEMPTS="1")
    require_account(args.account, env)

    def capture(row):
        response = observe("events", "test-event-pattern", {"EventPattern": row["pattern"], "Event": row["event"]}, env)
        return dict(row, **response)

    destination = Path(__file__).resolve().parents[2] / ".stackd/probes/eventbridge/patterns.json"
    observations = cases()
    if args.edges:
        observations = [row for row in observations if row["case"].startswith("edge_")]
        fixture["observations"] = [row for row in json.loads(destination.read_text())["observations"] if not row["case"].startswith("edge_")]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for row in pool.map(capture, observations):
            fixture["observations"].append(row)
            print(row["case"] + ": " + row["code"], flush=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(fixture, indent=2) + "\n")


if __name__ == "__main__":
    main()
