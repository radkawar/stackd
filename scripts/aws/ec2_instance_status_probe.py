#!/usr/bin/env python3
"""Capture one owned EC2 guest's real status checks and minute CloudWatch metrics.

Reuse InstanceCapture's account guard, isolated network, bounded launch and durable
ownership/cleanup ledger. The guest takes its NIC down after a bounded healthy
window and restores it using an independent local systemd timer. No SSH, public
network, credentials endpoint, synthetic health samples or account changes.
The SG denies all ordinary ingress/egress throughout the same experiment.
"""
import argparse
import base64
import datetime
import json
from pathlib import Path
import signal
import time

from ec2_instances_probe import InstanceCapture, console_records, interrupt
from ebs_encryption_probe import CONFIG, Capture, now, safe
from ebs_volume_controls_probe import sanitized

DOCS = [
    "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstanceStatus.html",
    "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_InstanceStatus.html",
    "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_InstanceStatusDetails.html",
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring-system-instance-status-check.html",
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/viewing_metrics_with_cloudwatch.html#status-check-metrics",
    "https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_GetMetricStatistics.html",
]
METRICS = ("StatusCheckFailed", "StatusCheckFailed_Instance", "StatusCheckFailed_System", "StatusCheckFailed_AttachedEBS")

GUEST = r'''#!/usr/bin/python3
import datetime,json,pathlib,subprocess,sys,time
boot=pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
def command(args,check=True):
    result=subprocess.run(args,capture_output=True,text=True,timeout=30)
    if check and result.returncode: raise RuntimeError("command failed: "+args[0]+" "+str(result.returncode))
    return {"argv":args,"code":result.returncode,"stdout":result.stdout.strip(),"stderr":result.stderr.strip()}
def emit(phase,nic,extra=None):
    record={"boot_id":boot+"-"+phase,"kernel_boot_id":boot,"boot_count":1,"phase":phase,
        "at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"monotonic":time.monotonic(),"nic":nic,
        "link":json.loads(command(["ip","-j","link","show","dev",nic])["stdout"]),
        "addresses":json.loads(command(["ip","-j","address","show","dev",nic])["stdout"])}
    if extra: record.update(extra)
    with open("/dev/console","w") as console: console.write("STACKD_GUEST "+json.dumps(record,separators=(",",":"))+"\n")
def restore(nic):
    rows=[command(["ip","link","set","dev",nic,"arp","on","up"],False),
        command(["systemctl","start","systemd-networkd"],False),
        command(["networkctl","reconfigure",nic],False)]
    time.sleep(5)
    emit("restored",nic,{"restore_commands":rows,"local_timer":True})
if len(sys.argv)>1 and sys.argv[1]=="--restore":
    restore(sys.argv[2])
    raise SystemExit()
routes=json.loads(command(["ip","-j","route","show","default"])["stdout"])
nic=next(row["dev"] for row in routes if row.get("dev")!="lo")
healthy_delay,down_seconds=map(int,sys.argv[1:3])
emit("ready",nic,{"healthy_delay_seconds":healthy_delay,"nic_down_seconds":down_seconds})
time.sleep(healthy_delay)
# Install a separate local restore timer before changing connectivity. It survives
# this process dying and requires neither network access nor the control plane.
command(["systemd-run","--unit=stackd-health-restore","--on-active="+str(down_seconds)+"s","--timer-property=AccuracySec=1s",
    "/usr/bin/python3","/root/stackd-status-probe.py","--restore",nic])
emit("before-down",nic)
try:
    command(["systemctl","stop","systemd-networkd"])
    command(["ip","link","set","dev",nic,"arp","off","down"])
    emit("nic-down",nic)
    time.sleep(down_seconds+20)
finally:
    # The independent timer is primary; this local fallback also needs no network.
    link=json.loads(command(["ip","-j","link","show","dev",nic])["stdout"])[0]
    if "UP" not in link["flags"] or "NOARP" in link["flags"]: restore(nic)
emit("finished",nic)
'''


class StatusCapture(InstanceCapture):
    def __init__(self, args):
        super().__init__(args)
        self.clients["cloudwatch"] = self.session.client("cloudwatch", config=CONFIG)
        if not args.cleanup_only and not args.audit_only:
            self.data.update(scope="One isolated owned t3.nano Linux guest, 8-GiB gp3 root; local timed NIC/ARP loss and restoration; native status API and CloudWatch observations",
                guest_program=GUEST, documentation=DOCS,
                reused_evidence=[{"path": "testdata/aws/ec2/instances_lifecycle.json",
                    "labels": ["running-status", "stopped-status", "stopped-status-default", "post-reboot-status"],
                    "observed": "Initialization, stopped default exclusion/not-applicable, attached EBS omission before first result"}],
                experiment={"guest_healthy_delay_seconds": 420, "guest_nic_down_seconds": 480,
                    "running_observation_seconds": 1500, "status_poll_seconds": 30, "metric_period_seconds": 60,
                    "network_boundary": "No SG ingress/egress rules, no public IP, NAT or internet gateway. Healthy status here is not evidence of IP/SSH/SG admission.",
                    "metric_boundary": "Exact native datapoints only. Missing samples and unsampled transitions are not fabricated; API observation times do not establish detection latency guarantees."})
            self.data["bounds"]["max_simultaneous_instances"] = 1
            if args.recovery_after:
                prior = json.loads(args.recovery_after.read_text())
                if prior["account"] != self.data["account"] or prior["region"] != args.region or not prior["cleanup"].get("complete"):
                    raise RuntimeError("Verified same-account prior cleanup is required before a sequential recovery capture")
                self.data["experiment"].update(guest_healthy_delay_seconds=240, guest_nic_down_seconds=300,
                    running_observation_seconds=1080, previous_fixture=str(args.recovery_after))
                self.data["reused_evidence"].append({"path": str(args.recovery_after),
                    "observed": "Prior initialization, healthy, impaired and terminated status/metrics; no prior resources remain. Admission matrix is not repeated."})
        self.last_status = None
        self.save()

    def observe(self, label, service, method, parameters=None, **kwargs):
        # Capture the parsed SDK envelope before the shared helper extracts its
        # ResponseMetadata. Keep its existing calls/ownership/error convention.
        client = kwargs.get("client") or self.clients[service]
        operation = client.meta.method_to_api_mapping[method]
        event = "after-call." + client.meta.service_model.service_id.hyphenize() + "." + operation
        envelopes = []
        def retain(parsed, **unused):
            envelopes.append(safe(parsed))
        client.meta.events.register_last(event, retain)
        try:
            if self.args.inputs_only:
                return Capture.observe(self, label, service, method, parameters, **kwargs)
            return super().observe(label, service, method, parameters, **kwargs)
        finally:
            client.meta.events.unregister(event, retain)
            if envelopes and self.data["calls"] and self.data["calls"][-1]["label"] == label:
                self.data["calls"][-1]["sdk_response"] = envelopes[-1]
                self.save()

    def status(self, iid, label, **extra):
        result = self.ec2(label, "describe_instance_status", dict(InstanceIds=[iid], **extra))
        signature = json.dumps(safe(result.get("InstanceStatuses", [])), sort_keys=True)
        if signature != self.last_status:
            print("STATUS " + now() + " " + signature, flush=True)
            self.last_status = signature
        return result

    def console_once(self, iid, label):
        result = self.ec2(label, "get_console_output", {"InstanceId": iid, "Latest": True})
        for record in console_records(result.get("Output", "")):
            if not any(row["guest"]["boot_id"] == record["boot_id"] for row in self.data["guest_observations"]):
                self.data["guest_observations"].append({"instance": iid, "call": label, "guest": record})
                print("GUEST " + json.dumps(record, sort_keys=True), flush=True)
        self.save()

    def metrics(self, iid, label):
        for name in METRICS:
            self.observe(label + "-" + name, "cloudwatch", "get_metric_statistics", {
                "Namespace": "AWS/EC2", "MetricName": name,
                "Dimensions": [{"Name": "InstanceId", "Value": iid}],
                "StartTime": datetime.datetime.fromisoformat(self.data["experiment_started_at"]),
                "EndTime": datetime.datetime.now(datetime.timezone.utc), "Period": 60,
                "Statistics": ["Minimum", "Maximum", "Average", "Sum", "SampleCount"]})

    def filters(self, iid, label):
        for name, values in (
            ("instance-state-name", ["running"]), ("instance-state-code", ["16"]),
            ("availability-zone", [self.data["zone"]]), ("instance-status.status", ["ok"]),
            ("instance-status.status", ["impaired"]), ("instance-status.reachability", ["passed"]),
            ("instance-status.reachability", ["failed"]), ("system-status.status", ["ok"]),
            ("attached-ebs-status.status", ["ok"]), ("instance-status.status", ["ok", "impaired"]),
            ("instance-status.status", ["not-a-status"]), ("unknown-status-filter", ["ok"]),
        ):
            self.status(iid, label + "-" + name + "-" + "-".join(values), IncludeAllInstances=True,
                Filters=[{"Name": name, "Values": values}])
        self.status(iid, label + "-filters-and", IncludeAllInstances=True, Filters=[
            {"Name": "instance-status.status", "Values": ["ok"]},
            {"Name": "system-status.status", "Values": ["impaired"]}])

    def admission(self, iid):
        self.status(iid, "admission-dry-run", DryRun=True)
        self.status(iid, "admission-ids-max-results", MaxResults=5)
        self.status(iid, "admission-ids-next-token", NextToken="not-a-token")
        self.ec2("admission-malformed-id", "describe_instance_status", {"InstanceIds": ["invalid"], "IncludeAllInstances": True})
        self.ec2("admission-missing-id", "describe_instance_status", {"InstanceIds": ["i-00000000000000000"], "IncludeAllInstances": True})
        self.ec2("admission-mixed-missing-id", "describe_instance_status", {"InstanceIds": [iid, "i-00000000000000000"], "IncludeAllInstances": True})
        self.ec2("admission-duplicate-ids", "describe_instance_status", {"InstanceIds": [iid, iid], "IncludeAllInstances": True})
        for maximum in (0, 1, 5, 1000, 1001):
            self.ec2("admission-page-size-" + str(maximum), "describe_instance_status", {
                "IncludeAllInstances": True, "MaxResults": maximum,
                "Filters": [{"Name": "instance-id", "Values": [iid]}]})
        self.ec2("admission-invalid-next-token", "describe_instance_status", {
            "IncludeAllInstances": True, "MaxResults": 5, "NextToken": "not-a-token",
            "Filters": [{"Name": "instance-id", "Values": [iid]}]})

    def inputs(self):
        self.data.update(scope="Read-only EC2 status/instance ID and pagination admission; no resources created, owned or modified",
            bounds={"max_simultaneous_instances": 0}, experiment=None)
        self.data.pop("guest_program", None)
        self.data.pop("reused_evidence", None)
        variants = [
            "0" * 8, "00000001", "12345678", "7fffffff", "80000000", "abcdef12", "ffffffff",
            "0" * 17, "0" * 16 + "1", "0123456789abcdef0", "01abcdef123456789",
            "07fffffffffffffff", "08000000000000000", "0ffffffffffffffff",
            "10000000000000000", "123456789abcdef01", "7ffffffffffffffff",
            "80000000000000000", "fffffffffffffffff",
            "1234567", "123456789", "0123456789abcdef", "00123456789abcdef0",
            "00123456789abcdef01", "0123456789abcdeF0", "0123456789abcdefg",
        ]
        for suffix in variants:
            iid = "i-" + suffix
            for method in ("describe_instance_status", "describe_instances"):
                parameters = {"InstanceIds": [iid]}
                if method == "describe_instance_status":
                    parameters["IncludeAllInstances"] = True
                self.ec2("id-shape-" + suffix + "-" + method, method, parameters)
        for maximum in (0, 1, 4, 5, 1000, 1001, 10000):
            self.ec2("page-valid-filter-" + str(maximum), "describe_instance_status", {
                "IncludeAllInstances": True, "MaxResults": maximum,
                "Filters": [{"Name": "availability-zone", "Values": ["us-east-1a"]}]})
        self.data["cleanup"] = {"complete": True, "read_only": True, "finished_at": now(),
            "boundary": "Only DescribeInstanceStatus/DescribeInstances were invoked; no cleanup writes required."}
        self.data["capture_complete_at"] = now()
        self.save()

    def run(self):
        self.deadline = time.monotonic() + self.args.live_seconds
        signal.alarm(self.args.live_seconds)
        self.setup()
        request = self.request()
        request["BlockDeviceMappings"] = request["BlockDeviceMappings"][:1]
        request["BlockDeviceMappings"][0]["Ebs"]["DeleteOnTermination"] = True
        request["Monitoring"] = {"Enabled": False}
        experiment = self.data["experiment"]
        request["UserData"] = "#!/bin/bash\nset -eu\numask 077\nprintf '%s' '" + base64.b64encode(GUEST.encode()).decode() + "' | base64 -d > /root/stackd-status-probe.py\npython3 /root/stackd-status-probe.py " + str(experiment["guest_healthy_delay_seconds"]) + " " + str(experiment["guest_nic_down_seconds"]) + "\n"
        if self.data["owned"]["instances"]:
            raise RuntimeError("One-instance ownership limit reached")
        self.data["experiment_started_at"] = now()
        self.save()
        iid = self.launch("run-status-guest", request, required=True)["Instances"][0]["InstanceId"]
        started = time.monotonic()
        self.status(iid, "launch-status-all", IncludeAllInstances=True)
        self.status(iid, "launch-status-default")
        if not self.args.recovery_after:
            self.admission(iid)
        next_console = next_metrics = 0
        filtered = set()
        attempt = 0
        while time.monotonic() - started < experiment["running_observation_seconds"]:
            elapsed = time.monotonic() - started
            result = self.status(iid, "status-poll-" + str(attempt), IncludeAllInstances=True)
            statuses = result.get("InstanceStatuses", [])
            if statuses and not self.args.recovery_after:
                current = statuses[0].get("InstanceStatus", {}).get("Status")
                if current in ("ok", "impaired") and current not in filtered:
                    filtered.add(current)
                    self.filters(iid, "filters-" + current)
            if elapsed >= next_console:
                self.console_once(iid, "console-" + str(attempt))
                next_console = elapsed + 60
            if elapsed >= next_metrics:
                self.metrics(iid, "metrics-" + str(attempt))
                next_metrics = elapsed + 180
            attempt += 1
            time.sleep(30)
        self.console_once(iid, "console-final-running")
        self.metrics(iid, "metrics-final-running")
        self.ec2("stop-status-guest", "stop_instances", {"InstanceIds": [iid]}, required=True)
        self.status(iid, "stopping-status-all", IncludeAllInstances=True)
        self.status(iid, "stopping-status-default")
        self.state(iid, "stopped", "status-guest-stopped", seconds=180)
        self.status(iid, "stopped-status-all", IncludeAllInstances=True)
        self.status(iid, "stopped-status-default")
        for all_instances in (False, True):
            self.status(iid, "stopped-state-filter-" + str(all_instances), IncludeAllInstances=all_instances,
                Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}])
        self.metrics(iid, "metrics-stopped")
        self.data["capture_complete_at"] = now()
        self.save()

    def cleanup(self):
        # Interruption starts cleanup once; repeated external signals must not
        # interrupt the inherited bounded cleanup before owned resources are gone.
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, signal.SIG_IGN)
        super().cleanup()
        for iid in self.data["owned"]["instances"]:
            self.status(iid, "terminated-status-all", IncludeAllInstances=True)
            self.status(iid, "terminated-status-default")
            if "experiment_started_at" in self.data:
                self.metrics(iid, "metrics-terminated")

    def handoff(self):
        super().handoff()
        path = self.args.output.with_name(self.args.output.stem + "_handoff.json")
        summary = json.loads(path.read_text())
        summary["guest_decoding"]["counter_boundary"] = "boot_id adds the console phase to kernel_boot_id for deduplication; boot_count is capture framing, not a disk/service/reboot counter. kernel_boot_id is the real Linux boot identity."
        self.data["guest_decoding"] = summary["guest_decoding"]
        self.save()
        summary["status_calls"] = [row for row in self.data["calls"] if row["operation"] == "DescribeInstanceStatus"]
        summary["metric_calls"] = [row for row in self.data["calls"] if row["operation"] == "GetMetricStatistics"]
        summary["experiment"] = self.data.get("experiment")
        summary["reused_evidence"] = self.data.get("reused_evidence")
        summary["unobserved"] = ["System infrastructure impairment", "Attached EBS impairment",
            "Whether an isolated attached EBS failure changes the aggregate StatusCheckFailed metric",
            "Scheduled events", "Multiple-page continuation with only one owned instance"]
        transitions = []
        previous = None
        for row in self.data["calls"]:
            if row["operation"] != "DescribeInstanceStatus" or not row["label"].startswith("status-poll-"):
                continue
            statuses = row.get("output", {}).get("InstanceStatuses", [])
            if statuses != previous:
                transitions.append({"label": row["label"], "observed_at": row["finished_at"], "statuses": statuses})
                previous = statuses
        summary["observed_status_transitions"] = transitions
        for expected in ("initializing", "ok", "impaired"):
            if not any(item.get("InstanceStatus", {}).get("Status") == expected for row in transitions for item in row["statuses"]):
                summary["unobserved"].append("Instance status " + expected)
        impaired = False
        recovered = False
        for row in transitions:
            for item in row["statuses"]:
                status = item.get("InstanceStatus", {}).get("Status")
                recovered = recovered or (impaired and status == "ok")
                impaired = impaired or status == "impaired"
        if not recovered:
            summary["unobserved"].append("Healthy status recovery following observed impairment")
        if not any(item.get("InstanceState", {}).get("Name") == "stopped"
            for row in summary["status_calls"] for item in row.get("output", {}).get("InstanceStatuses", [])):
            summary["unobserved"].append("Stopped state after this guest's healthy/impairment observations")
        phases = {row["guest"].get("phase") for row in summary["guest_observations"]}
        for phase in ("ready", "nic-down", "restored", "finished"):
            if phase not in phases:
                summary["unobserved"].append("Guest console phase " + phase)
        path.write_text(json.dumps(sanitized(summary), indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", default="us-east-1", choices=["us-east-1"])
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/ec2/instance_status.json"))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--cleanup-only", action="store_true")
    mode.add_argument("--inputs-only", action="store_true", help="Read-only ID/pagination admission; use a separate output fixture")
    mode.add_argument("--metrics-only", action="store_true", help="Read-only late metric harvest after verified cleanup")
    mode.add_argument("--recovery-after", type=Path, help="Shorter sequential recovery capture after this fixture's verified cleanup")
    parser.add_argument("--live-seconds", type=int, default=1800, choices=range(1200, 1801), metavar="1200..1800")
    args = parser.parse_args()
    args.audit_only = args.metrics_only
    capture = StatusCapture(args)
    if args.inputs_only:
        capture.inputs()
        return
    if args.metrics_only:
        if not capture.data["cleanup"].get("complete"):
            raise RuntimeError("Complete owned cleanup before read-only late metric harvest")
        for iid in capture.data["owned"]["instances"]:
            capture.metrics(iid, "metrics-post-cleanup-" + now())
        capture.handoff()
        return
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
        try:
            capture.cleanup()
        finally:
            capture.handoff()


if __name__ == "__main__":
    main()
