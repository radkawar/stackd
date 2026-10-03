#!/usr/bin/env python3
"""Capture an offline EC2 instance-type catalog and CPU credit references.

Read-only: verifies the explicit --account, pages DescribeInstanceTypes in us-east-1,
reads t3.nano regional/AZ offerings and four account credit defaults. It neither
creates infrastructure nor changes defaults. Raw SDK bodies/request timestamps
remain in calls; catalog.InstanceTypes contains sorted, otherwise unchanged SDK
InstanceTypeInfo bodies without request IDs or pagination tokens. Official CPU
credit rates are parsed from the retained AWS documentation, not inferred from
hardware metadata. Existing output fixtures are never overwritten.
"""
import argparse
from decimal import Decimal
import json
from pathlib import Path
import re
import urllib.request

from ebs_encryption_probe import Capture, now
from ebs_volume_controls_probe import sanitized

CREDIT_DOC = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/burstable-credits-baseline-concepts.html"
DOCS = ["https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_" + name + ".html" for name in (
    "DescribeInstanceTypes", "DescribeInstanceTypeOfferings", "GetDefaultCreditSpecification")] + [CREDIT_DOC]


def credit_table(markdown):
    rows = []
    source_lines = []
    in_table = False
    for line in markdown.splitlines():
        if line.startswith("|") and "CPU credits earned per hour" in line and "Baseline utilization" in line:
            in_table = True
        if not in_table:
            continue
        if not line.startswith("|"):
            break
        source_lines.append(line)
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if not cells or not re.fullmatch(r"t[a-z0-9]*\.[a-z0-9]+", cells[0]):
            continue
        if len(cells) != 5:
            raise ValueError("AWS CPU credit table changed column count")
        values = []
        for cell in cells[1:]:
            match = re.match(r"^(\d+(?:\.\d+)?)", cell)
            if not match:
                raise ValueError("AWS CPU credit table contains an unrecognized numeric cell")
            values.append(Decimal(match[1]))
        earned, maximum, vcpus, baseline = values
        if maximum != earned * 24 or earned != vcpus * baseline * Decimal("0.6"):
            raise ValueError("AWS CPU credit table violates its documented units; retain raw source for review")
        number = lambda value: int(value) if value == int(value) else float(value)
        rows.append({"InstanceType": cells[0], "CpuCreditsEarnedPerHour": number(earned),
            "MaximumEarnedCredits": number(maximum), "VCpus": int(vcpus),
            "BaselineUtilizationPerVCpuPercent": number(baseline), "SourceCells": cells})
    if not rows:
        raise ValueError("No official CPU credit table was parsed")
    names = [row["InstanceType"] for row in rows]
    if len(set(names)) != len(names):
        raise ValueError("Official CPU credit table contains duplicate instance types")
    return {"rows": sorted(rows, key=lambda row: row["InstanceType"]), "source_table_markdown": "\n".join(source_lines),
        "units": "One CPU credit is one vCPU-minute at full utilization. Baseline is percent per vCPU; maximum is earned-credit accrual, not launch credits or unlimited surplus."}


class CatalogCapture(Capture):
    def __init__(self, args):
        if args.credit_output.exists():
            raise RuntimeError("Refusing to overwrite credit evidence")
        super().__init__(args)
        self.data.update(schema_version=1, prefix="stackd-ec2-instance-types-readonly", documentation=DOCS,
            scope="Read-only supported-in-us-east-1 instance-type catalog; native owned-account credit defaults; documentation-derived credit-rate table",
            owned={}, cleanup={"not_required": True, "reason": "No mutations or resource creation"},
            catalog={"InstanceTypes": []}, pagination={}, offerings={}, complete=False)
        self.data.pop("payload", None)
        self.data.pop("sessions", None)
        self.save()

    def save(self):
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.args.output.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(sanitized(self.data), indent=2) + "\n")
        temporary.replace(self.args.output)

    def pages(self, label, method, parameters, member):
        values = []
        token = None
        seen_tokens = set()
        page = 0
        while True:
            request = dict(parameters)
            if token:
                request["NextToken"] = token
            result = self.observe(label + "-page-" + str(page + 1), "ec2", method, request, required=True)
            values.extend(result.get(member, []))
            page += 1
            token = result.get("NextToken")
            if not token:
                self.data["pagination"][label] = {"pages": page, "items": len(values), "terminal_next_token_absent": True}
                self.save()
                return values
            if token in seen_tokens:
                raise RuntimeError("Native pagination repeated a token")
            seen_tokens.add(token)

    def run(self):
        types = self.pages("instance-types", "describe_instance_types", {"MaxResults": 100, "IncludeUnsupportedInRegion": False}, "InstanceTypes")
        names = [item["InstanceType"] for item in types]
        if len(set(names)) != len(names):
            raise RuntimeError("Paginated catalog contains duplicate instance types; no silent deduplication")
        self.data["catalog"] = {"InstanceTypes": sorted(types, key=lambda item: item["InstanceType"])}
        self.data["catalog_boundary"] = "All pages for this Region with IncludeUnsupportedInRegion=false. No unqueried Region, unsupported type, capacity availability or executable-runtime support is inferred. SDK response bodies are retained unchanged except deterministic outer type ordering."
        self.save()
        for location in ("region", "availability-zone", "availability-zone-id"):
            rows = self.pages("t3-nano-offerings-" + location, "describe_instance_type_offerings", {
                "LocationType": location, "Filters": [{"Name": "instance-type", "Values": ["t3.nano"]}], "MaxResults": 1000}, "InstanceTypeOfferings")
            self.data["offerings"][location] = {"InstanceTypeOfferings": sorted(rows, key=lambda row: row["Location"])}
            self.save()
        credit_calls = []
        defaults = {}
        for family in ("t2", "t3", "t3a", "t4g"):
            response = self.observe("credit-default-" + family, "ec2", "get_default_credit_specification", {"InstanceFamily": family})
            credit_calls.append(self.data["calls"][-1])
            if response:
                defaults[family] = response
        credits = {key: self.data[key] for key in ("schema_version", "account", "region", "identity", "captured_at", "sdk", "documentation")}
        credits.update(scope="Native read-only account credit defaults and separately sourced official CPU-credit rate table",
            calls=credit_calls, defaults=defaults, defaults_boundary="Observed settings belong to this account/Region, not a universal assertion about pristine account defaults.", gaps=[])
        url = CREDIT_DOC.removesuffix(".html") + ".md"
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                body = response.read()
                retrieved_url = response.url
                headers = {key: response.headers[key] for key in ("Content-Type", "Last-Modified", "ETag") if key in response.headers}
            markdown = body.decode("utf-8")
            credits["credit_table"] = {"source_url": CREDIT_DOC, "retrieval_url": retrieved_url, "retrieved_at": now(),
                "response_headers": headers,
                "source_markdown": markdown, **credit_table(markdown)}
            documented = {row["InstanceType"] for row in credits["credit_table"]["rows"]}
            credits["credit_table"]["documented_types_absent_from_regional_catalog"] = sorted(documented - set(names))
            credits["credit_table"]["regional_burstable_types_absent_from_table"] = sorted(item["InstanceType"] for item in types
                if item.get("BurstablePerformanceSupported") and item["InstanceType"] not in documented)
        except Exception as error:
            credits["gaps"].append({"source_url": CREDIT_DOC, "retrieval_url": url, "error_type": type(error).__name__, "message": str(error)})
        credits["capture_complete_at"] = now()
        self.args.credit_output.parent.mkdir(parents=True, exist_ok=True)
        self.args.credit_output.write_text(json.dumps(sanitized(credits), indent=2) + "\n")
        self.data.update(complete=True, capture_complete_at=now(), credit_fixture=str(self.args.credit_output))
        self.save()
        print(json.dumps({"instance_types": len(types), "pages": self.data["pagination"]["instance-types"]["pages"],
            "credit_rows": len(credits.get("credit_table", {}).get("rows", [])), "credit_gaps": credits["gaps"]}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", default="us-east-1", choices=["us-east-1"])
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/ec2/instance_types.json"))
    parser.add_argument("--credit-output", type=Path, default=Path(".stackd/probes/ec2/instance_credit_defaults.json"))
    args = parser.parse_args()
    args.cleanup_only = False
    args.audit_only = False
    capture = CatalogCapture(args)
    try:
        capture.run()
    except Exception as error:
        capture.data["failure"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        capture.save()
        raise


if __name__ == "__main__":
    main()
