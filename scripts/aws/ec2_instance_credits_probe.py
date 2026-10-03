#!/usr/bin/env python3
"""CPU-credit evidence: readonly APIs, or one bounded owned Linux resize sequence."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import signal
import time
import urllib.request

from ebs_encryption_probe import CONFIG, Capture, now
from ec2_instances_probe import InstanceCapture, interrupt
from ebs_volume_controls_probe import sanitized

DOCS = ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/" + name + ".html" for name in (
    "burstable-performance-instances-standard-mode-concepts",
    "burstable-performance-instances-unlimited-mode-concepts",
    "burstable-performance-instances-how-to",
    "burstable-credits-baseline-concepts")]
DOCS += ["https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_" + name + ".html" for name in (
    "DescribeInstanceCreditSpecifications", "ModifyInstanceCreditSpecification",
    "GetDefaultCreditSpecification", "ModifyDefaultCreditSpecification")]


class CreditCapture(Capture):
    def __init__(self, args):
        super().__init__(args)
        self.data.update(schema_version=1, prefix="stackd-ec2-credits-readonly", documentation=DOCS,
            scope="Read-only defaults/validation and dry-run modification admission; no instances, credentials, defaults or standing resources changed",
            owned={}, cleanup={"not_required": True, "reason": "No mutations or resource creation"}, sources=[], complete=False)
        self.data.pop("payload", None)
        self.data.pop("sessions", None)
        self.save()

    def save(self):
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.args.output.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(sanitized(self.data), indent=2) + "\n")
        temporary.replace(self.args.output)

    def metrics_after_cleanup(self, path):
        source = json.loads(path.read_text())
        if source["account"] != self.data["account"] or source["region"] != self.args.region or not source["cleanup"].get("complete"):
            raise RuntimeError("Metric source must be this account/Region's completely cleaned owned experiment")
        instances = source["owned"]["instances"]
        if len(instances) != 1:
            raise RuntimeError("Expected exactly the one owned resize instance")
        if self.args.terminal_transitions:
            described = self.observe("owned-terminal-before-change", "ec2", "describe_instances", {"InstanceIds": instances}, required=True)
            terminal = [item for reservation in described.get("Reservations", []) for item in reservation.get("Instances", [])]
            if not terminal or any(item["State"]["Name"] != "terminated" for item in terminal):
                raise RuntimeError("Refusing mode transition on anything except the owned terminated tombstone")
            self.data.update(scope="CPU-credit mode transition on this probe's owned, verified-terminated tombstone only; restore original standard mode in finally, no VMM or default mutations",
                source_fixture=str(path), source_instance=instances[0])
            try:
                self.observe("owned-terminated-change-unlimited", "ec2", "modify_instance_credit_specification",
                    {"InstanceCreditSpecifications": [{"InstanceId": instances[0], "CpuCredits": "unlimited"}]}, required=True)
                self.observe("owned-terminated-describe-unlimited", "ec2", "describe_instance_credit_specifications", {"InstanceIds": instances}, required=True)
            finally:
                self.observe("owned-terminated-restore-standard", "ec2", "modify_instance_credit_specification",
                    {"InstanceCreditSpecifications": [{"InstanceId": instances[0], "CpuCredits": "standard"}]}, required=True)
                self.observe("owned-terminated-describe-restored", "ec2", "describe_instance_credit_specifications", {"InstanceIds": instances}, required=True)
            self.data.update(complete=True, capture_complete_at=now())
            self.save()
            return
        self.clients["cloudwatch"] = self.session.client("cloudwatch", config=CONFIG)
        queries = [{"Id": identifier, "MetricStat": {"Metric": {"Namespace": "AWS/EC2", "MetricName": name,
            "Dimensions": [{"Name": "InstanceId", "Value": instances[0]}]}, "Period": 60, "Stat": statistic}}
            for identifier, name, statistic in (("balance", "CPUCreditBalance", "Average"), ("usage", "CPUCreditUsage", "Sum"),
                ("surplus", "CPUSurplusCreditBalance", "Average"), ("charged", "CPUSurplusCreditsCharged", "Sum"),
                ("utilization", "CPUUtilization", "Average"))]
        self.data.update(scope="Post-cleanup metric harvest and credit-API outcomes on the owned terminated instance only; 60-second buckets preserve sparse five-minute source timestamps, not inferred one-minute publication",
            source_fixture=str(path), source_instance=instances[0],
            cleanup={"not_required": True, "reason": "Source cleanup verified; no new resources, live VMM or account-default changes"})
        metrics = self.observe("post-cleanup-source-metrics", "cloudwatch", "get_metric_data", {"MetricDataQueries": queries,
            "StartTime": datetime.datetime.fromisoformat(source["launch_requested_at"]).replace(second=0, microsecond=0),
            "EndTime": datetime.datetime.now(datetime.timezone.utc), "ScanBy": "TimestampAscending"}, required=True)
        if source.get("resize_starts"):
            balances = next(row for row in metrics["MetricDataResults"] if row["Id"] == "balance")
            comparisons = []
            for transition in source["resize_starts"]:
                start = datetime.datetime.fromisoformat(transition["requested_at"])
                end = min([datetime.datetime.fromisoformat(row["started_at"]) for row in source["calls"]
                    if row["operation"] == "StopInstances" and datetime.datetime.fromisoformat(row["started_at"]) > start]
                    + [datetime.datetime.fromisoformat(source["cleanup"]["started_at"])])
                rate = {"t3a.micro": 12, "t3.nano": 6}[transition["type"]]
                points = []
                for at, value in zip(balances["Timestamps"], balances["Values"]):
                    # A full extra 60-second bucket plus zero CPU usage gives an
                    # upper bound on credits possible after a hypothetical reset.
                    upper_at = at + datetime.timedelta(seconds=60)
                    if at > start and upper_at <= end:
                        maximum = (upper_at - start).total_seconds() * rate / 3600
                        points.append({"at": at.isoformat(), "balance": value, "zero_reset_maximum": maximum,
                            "excludes_zero_reset": value > maximum})
                comparisons.append(dict(transition, points=points, excludes_zero_reset=any(point["excludes_zero_reset"] for point in points)))
            self.data["assessment"] = {"method": "Upper bound from StartInstances request to metric bucket end, assuming no CPU use; no launch credits for T3/T3a. A larger observed balance excludes a zero reset, but does not establish exact nanosecond carry or reduced-cap behavior.",
                "transitions": comparisons, "conclusive": all(row["excludes_zero_reset"] for row in comparisons),
                "missing_samples": "No absence-to-zero inference; a phase without discriminating points remains inconclusive."}
            self.save()
        described = self.observe("owned-terminal-state", "ec2", "describe_instances", {"InstanceIds": instances})
        terminal = [item for reservation in described.get("Reservations", []) for item in reservation.get("Instances", [])]
        if terminal and all(item["State"]["Name"] == "terminated" for item in terminal):
            for label, specification in (("standard", {"InstanceId": instances[0], "CpuCredits": "standard"}),
                ("invalid", {"InstanceId": instances[0], "CpuCredits": "invalid"}),
                ("missing-mode", {"InstanceId": instances[0]})):
                self.observe("owned-terminated-modify-" + label, "ec2", "modify_instance_credit_specification",
                    {"InstanceCreditSpecifications": [specification]})
            self.observe("owned-terminal-credit-description", "ec2", "describe_instance_credit_specifications", {"InstanceIds": instances})
        self.data.update(complete=True, capture_complete_at=now())
        self.save()

    def run(self):
        for family in ("t2", "t3", "t3a", "t4g", "t8i", "m5", "T3", ""):
            self.observe("default-" + (family or "empty"), "ec2", "get_default_credit_specification", {"InstanceFamily": family})
        self.observe("default-missing", "ec2", "get_default_credit_specification", {})
        for credits in ("standard", "unlimited", "STANDARD", "invalid", ""):
            self.observe("default-dry-" + (credits or "empty"), "ec2", "modify_default_credit_specification",
                {"InstanceFamily": "t3", "CpuCredits": credits, "DryRun": True})
        self.observe("default-dry-invalid-family", "ec2", "modify_default_credit_specification",
            {"InstanceFamily": "m5", "CpuCredits": "standard", "DryRun": True})
        for label, parameters in (
            ("describe-malformed", {"InstanceIds": ["not-an-instance"]}),
            ("describe-missing", {"InstanceIds": ["i-00000000000000000"]}),
            ("describe-dry-missing", {"InstanceIds": ["i-00000000000000000"], "DryRun": True}),
            ("describe-invalid-filter", {"Filters": [{"Name": "cpu-credits", "Values": ["standard"]}]}),
            ("describe-page-small", {"MaxResults": 4}),
            ("describe-page-large", {"MaxResults": 1001}),
            ("describe-id-and-page", {"InstanceIds": ["i-00000000000000000"], "MaxResults": 5})):
            self.observe(label, "ec2", "describe_instance_credit_specifications", parameters)
        for label, specifications in (
            ("empty", []),
            ("missing", [{"InstanceId": "i-00000000000000000", "CpuCredits": "standard"}]),
            ("malformed", [{"InstanceId": "not-an-instance", "CpuCredits": "standard"}]),
            ("invalid-mode", [{"InstanceId": "i-00000000000000000", "CpuCredits": "invalid"}]),
            ("missing-mode", [{"InstanceId": "i-00000000000000000"}])):
            self.observe("modify-dry-" + label, "ec2", "modify_instance_credit_specification",
                {"InstanceCreditSpecifications": specifications, "DryRun": True})
        for source_url in DOCS:
            url = source_url.removesuffix(".html") + ".md"
            with urllib.request.urlopen(url, timeout=30) as response:
                body = response.read()
                source = {"source_url": source_url, "retrieval_url": response.url, "retrieved_at": now(),
                    "source_sha256": hashlib.sha256(body).hexdigest(), "source_markdown": body.decode("utf-8")}
            self.data["sources"].append(source)
            self.save()
        self.data.update(complete=True, capture_complete_at=now(),
            limits="No timing or CPU metering evidence: policy guarantees are official documentation, API validation/default outcomes are native. All Modify calls set DryRun=true.")
        self.save()
        print(json.dumps({"calls": len(self.data["calls"]), "sources": len(self.data["sources"]), "complete": True}), flush=True)


class ResizeCreditCapture(InstanceCapture):
    def __init__(self, args):
        super().__init__(args)
        self.clients["cloudwatch"] = self.session.client("cloudwatch", config=CONFIG)
        if not args.cleanup_only:
            self.data.update(scope="One owned T3 Standard instance: launch t3.nano, observe positive native credit balance, stop, resize to t3.micro, restart. No public IP, NAT, IAM roles, default mutations or CPU stress.",
                documentation=DOCS, metric_polls=[], assessment={"conclusive": False},
                bounds={"max_instances_total": 1, "experiment_seconds": args.live_seconds,
                    "cleanup_wait_seconds": 600, "initial_type": "t3.nano", "resize_type": "t3.micro", "public_network": False},
                guest_program="#!/bin/bash\nprintf 'STACKD_CREDIT_IDLE_READY\\n' >/dev/console\n")
            if args.transitions:
                self.data.update(scope="One owned t3.micro Standard guest, then t3a.micro and t3.nano starts. Stopped-only fixed-performance and T2 type/mode observations; no fixed-performance or T2 start. Positive earned-credit conservation, no public networking or account-default changes.",
                    bounds={"max_instances_total": 1, "experiment_seconds": args.live_seconds,
                        "cleanup_wait_seconds": 600, "running_types": ["t3.micro", "t3a.micro", "t3.nano"],
                        "root_gib": 8, "root_type": "gp3", "public_network": False},
                    guest_program="""#!/bin/bash
mkdir -p /var/lib/cloud/scripts/per-boot
cat > /var/lib/cloud/scripts/per-boot/stackd-credit <<'GUEST'
#!/bin/bash
printf 'STACKD_CREDIT_BOOT cpus=%s mem_kib=%s boot_id=%s\\n' "$(nproc)" "$(sed -n 's/MemTotal: *\\([0-9]*\\).*/\\1/p' /proc/meminfo)" "$(cat /proc/sys/kernel/random/boot_id)" >/dev/console
GUEST
chmod 700 /var/lib/cloud/scripts/per-boot/stackd-credit
/var/lib/cloud/scripts/per-boot/stackd-credit
""")
            if args.unlimited_detour:
                self.data.update(scope="One owned t3.nano Unlimited guest with a stopped-only M5 detour. Repeated explicit-ID and filtered-default credit discovery; no balance-conservation or fixed-performance execution claim.",
                    bounds={"max_instances_total": 1, "experiment_seconds": args.live_seconds,
                        "cleanup_wait_seconds": 600, "running_types": ["t3.nano"],
                        "root_gib": 8, "root_type": "gp3", "public_network": False})
            self.save()

    def setup(self):
        parameter = self.observe("official-al2023", "ssm", "get_parameter",
            {"Name": "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"}, required=True)
        image = self.ec2("official-image", "describe_images",
            {"ImageIds": [parameter["Parameter"]["Value"]], "Owners": ["amazon"]}, required=True)["Images"][0]
        root = next(row["Ebs"] for row in image["BlockDeviceMappings"] if row["DeviceName"] == image["RootDeviceName"])
        if image["Architecture"] != "x86_64" or image["RootDeviceType"] != "ebs" or image["VirtualizationType"] != "hvm" or image.get("ProductCodes") or root["VolumeSize"] > 8:
            raise RuntimeError("Refusing nonordinary bounded official Linux image")
        self.data["source_image"] = image
        zones = self.ec2("available-zones", "describe_availability_zones",
            {"Filters": [{"Name": "zone-type", "Values": ["availability-zone"]}]}, required=True)
        self.data["zone"] = next(zone["ZoneName"] for zone in zones["AvailabilityZones"] if zone["State"] == "available")
        self.save()
        vpc = self.ec2("owned-vpc", "create_vpc", {"CidrBlock": "10.238.0.0/24",
            "TagSpecifications": self.tags("vpc")}, required=True)["Vpc"]["VpcId"]
        self.data["owned"]["vpc"] = vpc
        self.save()
        subnet = self.ec2("owned-subnet", "create_subnet", {"VpcId": vpc, "CidrBlock": "10.238.0.0/27",
            "AvailabilityZone": self.data["zone"], "TagSpecifications": self.tags("subnet")}, required=True)["Subnet"]["SubnetId"]
        self.data["owned"]["subnet"] = subnet
        self.save()
        group = self.ec2("owned-group", "create_security_group", {"VpcId": vpc, "GroupName": self.data["prefix"],
            "Description": "Isolated bounded CPU credit resize", "TagSpecifications": self.tags("security-group")}, required=True)["GroupId"]
        self.data["owned"]["group"] = group
        self.save()
        self.ec2("owned-remove-egress", "revoke_security_group_egress", {"GroupId": group,
            "IpPermissions": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}, required=True)
        self.ec2("isolated-routes", "describe_route_tables", {"Filters": [{"Name": "vpc-id", "Values": [vpc]}]}, required=True)

    def metric_poll(self, iid, phase):
        end = datetime.datetime.now(datetime.timezone.utc)
        start = datetime.datetime.fromisoformat(self.data["launch_requested_at"]).replace(second=0, microsecond=0)
        queries = []
        for identifier, name, statistic in (("balance", "CPUCreditBalance", "Average"), ("usage", "CPUCreditUsage", "Sum"),
            ("surplus", "CPUSurplusCreditBalance", "Average"), ("charged", "CPUSurplusCreditsCharged", "Sum"),
            ("utilization", "CPUUtilization", "Average")):
            queries.append({"Id": identifier, "MetricStat": {"Metric": {"Namespace": "AWS/EC2", "MetricName": name,
                "Dimensions": [{"Name": "InstanceId", "Value": iid}]}, "Period": 60 if self.args.transitions else 300, "Stat": statistic}})
        result = self.observe("credits-" + phase + "-" + str(len(self.data["metric_polls"])), "cloudwatch",
            "get_metric_data", {"MetricDataQueries": queries, "StartTime": start, "EndTime": end,
                "ScanBy": "TimestampAscending"}, required=True)
        points = {}
        for row in result.get("MetricDataResults", []):
            points[row["Id"]] = [{"at": str(at), "value": value} for at, value in zip(row.get("Timestamps", []), row.get("Values", []))]
        self.data["metric_polls"].append({"at": now(), "phase": phase, "points": points})
        self.save()
        return points

    def run(self):
        self.deadline = time.monotonic() + self.args.live_seconds
        self.data["experiment_deadline"] = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=self.args.live_seconds)).isoformat()
        self.save()
        signal.alarm(self.args.live_seconds)
        self.setup()
        image = self.data["source_image"]
        request = {"ImageId": image["ImageId"], "InstanceType": "t3.nano", "MinCount": 1, "MaxCount": 1,
            "CreditSpecification": {"CpuCredits": "unlimited" if self.args.unlimited_detour else "standard"},
            "Monitoring": {"Enabled": not self.args.unlimited_detour},
            "NetworkInterfaces": [{"DeviceIndex": 0, "SubnetId": self.data["owned"]["subnet"],
                "Groups": [self.data["owned"]["group"]], "AssociatePublicIpAddress": False, "DeleteOnTermination": True}],
            "BlockDeviceMappings": [{"DeviceName": image["RootDeviceName"],
                "Ebs": {"VolumeSize": 8, "VolumeType": "gp3", "DeleteOnTermination": True}}],
            "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
            "TagSpecifications": self.tags("instance", "volume", "network-interface"),
            "UserData": self.data["guest_program"], "ClientToken": self.data["prefix"] + "-credits"}
        self.data["launch_requested_at"] = now()
        self.save()
        iid = self.launch("owned-credit-instance", request, required=True)["Instances"][0]["InstanceId"]
        self.state(iid, "running", "credit-running")
        self.data["running_observed_at"] = now()
        self.save()
        if self.args.unlimited_detour:
            self.run_unlimited_detour(iid)
            return
        if self.args.transitions:
            # The shared launch guard admits nanos only. Resize the one owned
            # stopped guest before the first measured micro interval.
            self.ec2("bootstrap-stop", "stop_instances", {"InstanceIds": [iid]}, required=True)
            self.state(iid, "stopped", "bootstrap-stopped", seconds=180)
            self.ec2("bootstrap-micro", "modify_instance_attribute",
                {"InstanceId": iid, "InstanceType": {"Value": "t3.micro"}}, required=True)
            self.ec2("bootstrap-start", "start_instances", {"InstanceIds": [iid]}, required=True)
            self.state(iid, "running", "bootstrap-running", seconds=180)
            self.run_transitions(iid)
            return
        # Credit metrics are published at five-minute frequency even with
        # detailed monitoring. Missing datapoints never stand for zero credits.
        before = None
        pre_deadline = min(self.deadline - 600, time.monotonic() + 840)
        while time.monotonic() < pre_deadline:
            points = self.metric_poll(iid, "before-resize")
            positives = [point for point in points.get("balance", []) if point["value"] >= 0.5]
            if positives:
                before = positives[-1]
                break
            time.sleep(30)
        if before is None:
            self.data["assessment"] = {"conclusive": False, "reason": "No native CPUCreditBalance >=0.5 observed within pre-resize bound; resize not attempted, absence is not zero."}
            self.save()
            return
        self.data["positive_pre_stop_balance"] = before
        self.data["stop_requested_at"] = now()
        self.save()
        self.ec2("credit-stop", "stop_instances", {"InstanceIds": [iid]}, required=True)
        self.state(iid, "stopped", "credit-stopped", seconds=180)
        self.ec2("credit-mode-stopped", "describe_instance_credit_specifications", {"InstanceIds": [iid]}, required=True)
        self.ec2("credit-resize-micro", "modify_instance_attribute", {"InstanceId": iid, "InstanceType": {"Value": "t3.micro"}}, required=True)
        self.data["restart_requested_at"] = now()
        self.save()
        self.ec2("credit-restart", "start_instances", {"InstanceIds": [iid]}, required=True)
        self.state(iid, "running", "credit-micro-running", seconds=180)
        self.data["restart_running_observed_at"] = now()
        self.save()
        while time.monotonic() < self.deadline - 30:
            self.metric_poll(iid, "after-resize")
            time.sleep(30)
        self.data["assessment"] = {"conclusive": False, "reason": "Raw pre/post balance and actual usage retained for conservation-bound analysis; no automatic reset/carry inference from missing or delayed samples."}
        self.save()

    def run_unlimited_detour(self, iid):
        self.ec2("unlimited-before-stop", "describe_instance_credit_specifications", {"InstanceIds": [iid]}, required=True)
        self.ec2("unlimited-stop", "stop_instances", {"InstanceIds": [iid]}, required=True)
        self.state(iid, "stopped", "unlimited-stopped", seconds=180)
        for phase, typ in (("fixed", "m5.large"), ("restored", "t3.nano")):
            self.ec2(phase + "-resize", "modify_instance_attribute",
                {"InstanceId": iid, "InstanceType": {"Value": typ}}, required=True)
            until = min(self.deadline, time.monotonic() + 90)
            attempt = 0
            while time.monotonic() < until:
                observed = self.ec2(phase + "-type-" + str(attempt), "describe_instances",
                    {"InstanceIds": [iid]}, required=True)["Reservations"][0]["Instances"][0]
                if observed["InstanceType"] == typ:
                    break
                attempt += 1
                time.sleep(2)
            else:
                raise TimeoutError("Native stopped type did not publish within the capture bound")
            for sample in range(2):
                prefix = phase + "-" + str(sample)
                self.ec2(prefix + "-by-id", "describe_instance_credit_specifications", {"InstanceIds": [iid]}, required=True)
                filters = [{"Name": "instance-id", "Values": [iid]}]
                self.ec2(prefix + "-default", "describe_instance_credit_specifications", {"Filters": filters}, required=True)
                if sample == 0:
                    time.sleep(20)
        self.data.update(complete=True, capture_complete_at=now(),
            assessment={"conclusive": False, "reason": "Explicit and filtered-default projection rows retained; no CPU-balance claim."})
        self.save()

    def run_transitions(self, iid):
        # Publication can lag live execution. Fixed phase bounds leave enough
        # time for both starts; missing samples never become zero balances.
        for phase, seconds in (("initial-micro", 390), ("cross-family", 330), ("fixed-roundtrip-nano", 0)):
            until = min(self.deadline - 45, time.monotonic() + seconds) if seconds else self.deadline - 45
            while time.monotonic() < until:
                self.metric_poll(iid, phase)
                time.sleep(min(30, max(0, until - time.monotonic())))
            self.ec2("console-" + phase, "get_console_output", {"InstanceId": iid, "Latest": True})
            if phase == "fixed-roundtrip-nano":
                break
            self.ec2("stop-" + phase, "stop_instances", {"InstanceIds": [iid]}, required=True)
            self.state(iid, "stopped", "stopped-" + phase, seconds=180)
            types = ("t3a.micro",) if phase == "initial-micro" else ("m5.large", "t2.micro", "t3.nano")
            for typ in types:
                self.ec2("resize-" + typ, "modify_instance_attribute",
                    {"InstanceId": iid, "InstanceType": {"Value": typ}}, required=True)
                self.ec2("type-" + typ, "describe_instances", {"InstanceIds": [iid]}, required=True)
                self.ec2("credit-mode-" + typ, "describe_instance_credit_specifications", {"InstanceIds": [iid]}, required=True)
            next_phase = "cross-family" if phase == "initial-micro" else "fixed-roundtrip-nano"
            self.data.setdefault("resize_starts", []).append({"phase": next_phase, "type": types[-1], "requested_at": now()})
            self.save()
            self.ec2("start-" + next_phase, "start_instances", {"InstanceIds": [iid]}, required=True)
            self.state(iid, "running", "running-" + next_phase, seconds=180)
        self.data["assessment"] = {"conclusive": False, "reason": "Raw measured pre/post balances and usage require conservation analysis, potentially post-cleanup harvest. No reset/carry inference from absent samples.",
            "not_exercised": ["Balance above reduced cap", "T2 or non-burstable running", "Seven-day expiry", "T4g/T8i family transitions"]}
        self.data.update(complete=True, capture_complete_at=now())
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", choices=["us-east-1"], default="us-east-1")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--resize", action="store_true")
    parser.add_argument("--transitions", action="store_true", help="One micro cross-family and stopped fixed-performance roundtrip sequence")
    parser.add_argument("--unlimited-detour", action="store_true", help="One short Unlimited guest and stopped fixed-performance discovery boundary")
    parser.add_argument("--metric-source", type=Path)
    parser.add_argument("--terminal-transitions", action="store_true")
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--live-seconds", type=int, default=1200, choices=range(600, 1201), metavar="600..1200")
    args = parser.parse_args()
    args.audit_only = False
    if args.unlimited_detour and args.transitions:
        parser.error("--unlimited-detour and --transitions are distinct captures")
    if args.transitions or args.unlimited_detour:
        args.resize = True
    if args.terminal_transitions and not args.metric_source:
        parser.error("--terminal-transitions requires --metric-source")
    if args.metric_source and (args.resize or args.cleanup_only or args.output is None):
        parser.error("--metric-source requires an explicit new --output and no resize/cleanup mode")
    if args.output is None:
        args.output = Path(".stackd/probes/ec2/instance_credits_unlimited_detour.json" if args.unlimited_detour else
            ".stackd/probes/ec2/instance_credits_transitions.json" if args.transitions else
            ".stackd/probes/ec2/instance_credits_resize.json" if args.resize else ".stackd/probes/ec2/instance_credits_api.json")
    if args.metric_source:
        CreditCapture(args).metrics_after_cleanup(args.metric_source)
        return
    if not args.resize:
        if args.cleanup_only:
            parser.error("--cleanup-only requires --resize")
        CreditCapture(args).run()
        return
    capture = ResizeCreditCapture(args)
    for signum in (signal.SIGALRM, signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, interrupt)
    try:
        if not args.cleanup_only:
            capture.run()
    except Exception as error:
        capture.data["failure"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        capture.save()
        raise
    finally:
        capture.cleanup()


if __name__ == "__main__":
    main()
