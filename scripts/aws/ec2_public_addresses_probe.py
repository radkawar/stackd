#!/usr/bin/env python3
"""Capture native EC2 public IPv4 controls with exact, resumable ownership.

One t3.micro (8-GiB gp3, <=30-minute experiment plus bounded cleanup), at most
two EIP allocations, one fresh VPC/subnet/IGW and fresh ENIs. No standing resource
or account setting changes. The second EIP is released before auto-public launch,
so even including the ephemeral IPv4 at most two public addresses are live.

Run with PYTHONPATH=scripts/aws python3 -B -P. --cleanup-only resumes the output
ledger. --summarize-only is offline. Native IDs/times/raw responses stay native;
case labels and ordering are deterministic. No local emulator result is mixed in.
"""
import argparse
import json
from pathlib import Path
import signal
import time
import uuid

from ebs_encryption_probe import Capture, now
from ebs_volume_controls_probe import sanitized

OPERATIONS = ("AllocateAddress", "DescribeAddresses", "AssociateAddress", "DisassociateAddress", "ReleaseAddress",
              "UnassignPrivateIpAddresses", "DeleteNetworkInterface", "AssignPrivateIpAddresses")
DOCS = ["https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_" + name + ".html" for name in OPERATIONS] + [
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html",
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html",
    "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Internet_Gateway.html",
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/how-ec2-instance-stop-start-works.html",
    "https://docs.aws.amazon.com/ec2/latest/devguide/errors-overview.html",
]
MISSING_ALLOCATION = "eipalloc-00000000000000000"
MISSING_ASSOCIATION = "eipassoc-00000000000000000"
MISSING_ENI = "eni-00000000000000000"
MISSING_INSTANCE = "i-00000000000000000"


def interrupt(signum, frame):
    raise RuntimeError("Capture interrupted by signal " + str(signum))


class PublicAddressCapture(Capture):
    def __init__(self, args):
        if args.region != "us-east-1":
            raise RuntimeError("Only us-east-1 is authorized")
        args.audit_only = False
        super().__init__(args)
        if not args.cleanup_only:
            self.data.update(schema=1, prefix="stackd-public-addresses-" + uuid.uuid4().hex[:12],
                documentation=DOCS, source="native AWS only", documentation_reviewed_at=now(),
                scope="Exact-owned EC2 public IPv4 controls; one t3.micro and two total EIP allocations; no standing mutations",
                bounds={"instances": 1, "instance_type": "t3.micro", "eip_allocations": 2,
                        "live_public_ipv4_including_ephemeral": 2, "experiment_seconds": args.live_seconds,
                        "cleanup_seconds": 600},
                owned={"allocations": [], "interfaces": [], "instances": [], "volumes": []},
                aliases={}, snapshots={},
                gaps=["Quota exhaustion is not exercised: AWS documents default five EIPs per account/Region.",
                      "No BYOIP, IPAM, CoIP, Wavelength, cross-account transfer, dual-stack DNS or default-VPC mutation.",
                      "No IAM changes: UnauthorizedOperation is documented, not a captured denied-principal result.",
                      "Control-plane capture only; public packet reachability is not claimed."])
            self.data.pop("payload", None)
        self.raw = None
        self.clients["ec2"].meta.events.register("after-call.ec2.*", self.capture_raw)
        self.save()

    def capture_raw(self, http_response, **kwargs):
        self.raw = http_response.content.decode("utf-8")

    def save(self):
        self.args.output.parent.mkdir(parents=True, exist_ok=True)
        self.args.output.write_text(json.dumps(sanitized(self.data), indent=2) + "\n")

    def own(self, kind, identifier):
        if identifier not in self.data["owned"][kind]:
            self.data["owned"][kind].append(identifier)

    def ec2(self, label, method, parameters=None, *, required=False):
        parameters = parameters or {}
        owned = self.data["owned"]
        if method == "allocate_address" and not parameters.get("DryRun") and len(owned["allocations"]) >= 2:
            raise RuntimeError("Two-total-EIP allocation safety limit")
        if method == "run_instances":
            if owned["instances"] or parameters.get("InstanceType") != "t3.micro" or parameters.get("MaxCount") != 1:
                raise RuntimeError("One t3.micro safety limit")
        self.raw = None
        output = super().observe(label, "ec2", method, parameters)
        row = self.data["calls"][-1]
        row["sequence"] = len(self.data["calls"])
        if self.raw is not None:
            row["rawResponseBody"] = self.raw
        for operation, key, kind in (("allocate_address", "AllocationId", "allocations"),
                                     ("create_network_interface", "NetworkInterfaceId", "interfaces")):
            value = output.get("NetworkInterface", output)
            if method == operation and value.get(key):
                self.own(kind, value[key])
        for method_name, key, nested in (("create_vpc", "vpc", "Vpc"), ("create_subnet", "subnet", "Subnet"),
                                         ("create_internet_gateway", "gateway", "InternetGateway")):
            if method == method_name and nested in output:
                owned[key] = output[nested][nested + "Id"]
        if method == "run_instances":
            for instance in output.get("Instances", []):
                self.own("instances", instance["InstanceId"])
                for interface in instance.get("NetworkInterfaces", []):
                    self.own("interfaces", interface["NetworkInterfaceId"])
        if method in ("run_instances", "describe_instances"):
            instances = output.get("Instances", []) + [i for r in output.get("Reservations", []) for i in r["Instances"]]
            for instance in instances:
                if instance["InstanceId"] in owned["instances"]:
                    for mapping in instance.get("BlockDeviceMappings", []):
                        if mapping.get("Ebs", {}).get("VolumeId"):
                            self.own("volumes", mapping["Ebs"]["VolumeId"])
        self.save()
        if required and row["code"] != "Success":
            raise RuntimeError(label + ": " + row["code"])
        return output

    def tags(self, kind):
        return [{"ResourceType": kind, "Tags": [{"Key": "suite", "Value": self.data["prefix"]}]}]

    def aliases(self, **values):
        self.data["aliases"].update(values)
        self.save()

    def matrix(self, prefix, method, rows):
        for name, request in rows:
            for dry in (False, True):
                self.ec2(prefix + "-" + name + ("-dry" if dry else "-actual"), method, dict(request, DryRun=dry))

    def address(self, label, allocation):
        result = self.ec2(label, "describe_addresses", {"AllocationIds": [allocation]}, required=True)
        return result["Addresses"][0]

    def associate(self, label, allocation, interface, **extra):
        return self.ec2(label, "associate_address", dict(AllocationId=allocation, NetworkInterfaceId=interface, **extra))

    def disassociate(self, label, allocation):
        address = self.address(label + "-before", allocation)
        association = address.get("AssociationId")
        if association:
            self.ec2(label, "disassociate_address", {"AssociationId": association}, required=True)
        return association

    def snapshot(self, label, allocations, interfaces=(), instance=None):
        observation = {"addresses": [self.address(label + "-address-" + str(n), a) for n, a in enumerate(allocations)]}
        if interfaces:
            observation["interfaces"] = self.ec2(label + "-interfaces", "describe_network_interfaces",
                {"NetworkInterfaceIds": list(interfaces)})
        if instance:
            observation["instance"] = self.instance(label + "-instance", instance)
        self.data["snapshots"][label] = observation
        self.save()

    def instance(self, label, iid):
        output = self.ec2(label, "describe_instances", {"InstanceIds": [iid]}, required=True)
        return output["Reservations"][0]["Instances"][0]

    def state(self, label, iid, target):
        deadline = time.monotonic() + 240
        attempt = 0
        while time.monotonic() < deadline:
            instance = self.instance(label + "-" + str(attempt), iid)
            if instance["State"]["Name"] == target:
                return instance
            time.sleep(4)
            attempt += 1
        raise RuntimeError("Instance state deadline: " + target)

    def setup(self):
        zones = self.ec2("available-standard-zones", "describe_availability_zones",
            {"Filters": [{"Name": "zone-type", "Values": ["availability-zone"]}, {"Name": "state", "Values": ["available"]}]}, required=True)
        zone = sorted(zones["AvailabilityZones"], key=lambda value: value["ZoneName"])[0]["ZoneName"]
        vpc = self.ec2("create-owned-vpc", "create_vpc", {"CidrBlock": "10.237.42.0/24", "TagSpecifications": self.tags("vpc")}, required=True)["Vpc"]["VpcId"]
        subnet = self.ec2("create-owned-subnet", "create_subnet", {"VpcId": vpc, "CidrBlock": "10.237.42.0/24",
            "AvailabilityZone": zone, "TagSpecifications": self.tags("subnet")}, required=True)["Subnet"]["SubnetId"]
        for name, private in (("eni_a", "10.237.42.10"), ("eni_b", "10.237.42.20")):
            interface = self.ec2("create-owned-" + name, "create_network_interface", {"SubnetId": subnet,
                "PrivateIpAddress": private, "SecondaryPrivateIpAddressCount": 1,
                "Description": self.data["prefix"] + "-" + name, "TagSpecifications": self.tags("network-interface")}, required=True)["NetworkInterface"]
            secondary = next(p["PrivateIpAddress"] for p in interface["PrivateIpAddresses"] if not p["Primary"])
            self.aliases(**{name: interface["NetworkInterfaceId"], name + "_secondary": secondary, name + "_primary": private})
        for name, extra in (("eip_a", {"Domain": "vpc"}), ("eip_b", {})):
            value = self.ec2("allocate-" + name, "allocate_address", dict(extra, TagSpecifications=self.tags("elastic-ip")), required=True)
            self.aliases(**{name: value["AllocationId"], name + "_public": value["PublicIp"]})
        self.aliases(zone=zone)

    def admission(self):
        a = self.data["aliases"]
        allocation, interface = a["eip_a"], a["eni_a"]
        for name, request in (("default", {}), ("standard", {"Domain": "standard"}), ("bad-domain", {"Domain": "invalid"}),
                              ("bad-border", {"NetworkBorderGroup": "invalid"}), ("bad-pool", {"PublicIpv4Pool": "invalid"}),
                              ("bad-address", {"Address": "invalid"})):
            self.ec2("allocate-" + name + "-dry", "allocate_address", dict(request, DryRun=True))
        self.matrix("describe", "describe_addresses", [
            ("malformed", {"AllocationIds": ["bad"]}), ("missing", {"AllocationIds": [MISSING_ALLOCATION]}),
            ("mixed-missing", {"AllocationIds": [allocation, MISSING_ALLOCATION]}),
            ("bad-public", {"PublicIps": ["bad"]}), ("missing-public", {"PublicIps": ["192.0.2.1"]}),
            ("bad-filter", {"AllocationIds": [allocation], "Filters": [{"Name": "invalid", "Values": ["x"]}]})])
        self.matrix("associate", "associate_address", [
            ("missing-all", {}), ("missing-target", {"AllocationId": allocation}),
            ("missing-allocation", {"NetworkInterfaceId": interface}),
            ("both-targets", {"AllocationId": allocation, "NetworkInterfaceId": interface, "InstanceId": MISSING_INSTANCE}),
            ("both-address-selectors", {"AllocationId": allocation, "PublicIp": a["eip_a_public"], "NetworkInterfaceId": interface}),
            ("bad-allocation-bad-eni", {"AllocationId": "bad", "NetworkInterfaceId": "bad"}),
            ("missing-allocation-bad-eni", {"AllocationId": MISSING_ALLOCATION, "NetworkInterfaceId": "bad"}),
            ("missing-eni", {"AllocationId": allocation, "NetworkInterfaceId": MISSING_ENI}),
            ("missing-instance", {"AllocationId": allocation, "InstanceId": MISSING_INSTANCE}),
            ("unassigned-private", {"AllocationId": allocation, "NetworkInterfaceId": interface, "PrivateIpAddress": "10.237.42.250"}),
            ("malformed-private", {"AllocationId": allocation, "NetworkInterfaceId": interface, "PrivateIpAddress": "bad"}),
            ("public-selector", {"PublicIp": a["eip_a_public"], "NetworkInterfaceId": interface})])
        self.disassociate("admission-reset", allocation)
        for method, key, missing in (("disassociate_address", "AssociationId", MISSING_ASSOCIATION),
                                      ("release_address", "AllocationId", MISSING_ALLOCATION)):
            self.matrix(method, method, [("absent", {}), ("malformed", {key: "bad"}), ("missing", {key: missing})])
        self.ec2("release-bad-border", "release_address", {"AllocationId": allocation, "NetworkBorderGroup": "invalid"})
        self.ec2("describe-by-public", "describe_addresses", {"PublicIps": [a["eip_a_public"]]})
        self.ec2("describe-duplicate", "describe_addresses", {"AllocationIds": [allocation, allocation]})
        self.ec2("describe-intersection-selectors", "describe_addresses", {"AllocationIds": [allocation], "PublicIps": [a["eip_b_public"]]})
        for name, values in (("allocation-id", [allocation]), ("network-border-group", ["us-east-1"]),
                             ("tag:suite", [self.data["prefix"]]), ("tag-key", ["suite"]), ("public-ip", [a["eip_a_public"]])):
            self.ec2("describe-filter-" + name, "describe_addresses", {"AllocationIds": [allocation], "Filters": [{"Name": name, "Values": values}]})

    def interfaces(self):
        a = self.data["aliases"]
        ea, eb, na, nb = (a[k] for k in ("eip_a", "eip_b", "eni_a", "eni_b"))
        self.associate("associate-without-igw", ea, na)
        self.snapshot("without-igw", [ea, eb], [na, nb])
        gateway = self.ec2("create-owned-igw", "create_internet_gateway", {"TagSpecifications": self.tags("internet-gateway")}, required=True)["InternetGateway"]["InternetGatewayId"]
        self.ec2("attach-owned-igw", "attach_internet_gateway", {"InternetGatewayId": gateway, "VpcId": self.data["owned"]["vpc"]}, required=True)
        self.associate("associate-unattached-primary", ea, na)
        self.snapshot("unattached-primary", [ea, eb], [na, nb])
        self.associate("associate-same-target-false", ea, na, AllowReassociation=False)
        self.associate("associate-different-target-false", ea, nb, AllowReassociation=False)
        self.ec2("associate-different-target-false-dry", "associate_address", {"AllocationId": ea, "NetworkInterfaceId": nb, "AllowReassociation": False, "DryRun": True})
        self.snapshot("reassociation-refused", [ea, eb], [na, nb])
        self.associate("associate-different-target-default", ea, nb)
        self.associate("associate-back-explicit-true", ea, na, AllowReassociation=True)
        self.associate("replace-target-other-eip-false", eb, na, AllowReassociation=False)
        self.snapshot("target-displaced", [ea, eb], [na, nb])
        self.ec2("release-associated-nondefault", "release_address", {"AllocationId": eb})
        self.ec2("release-associated-nondefault-dry", "release_address", {"AllocationId": eb, "DryRun": True})
        self.associate("associate-secondary", ea, na, PrivateIpAddress=a["eni_a_secondary"])
        self.snapshot("two-eips-one-eni", [ea, eb], [na])
        for name, value in (("association-id", self.address("filter-association-source", ea).get("AssociationId", "missing")),
                            ("network-interface-id", na), ("private-ip-address", a["eni_a_secondary"]), ("network-interface-owner-id", self.args.account)):
            self.ec2("describe-filter-" + name, "describe_addresses", {"AllocationIds": [ea, eb], "Filters": [{"Name": name, "Values": [value]}]})
        self.ec2("unassign-eip-secondary", "unassign_private_ip_addresses", {"NetworkInterfaceId": na, "PrivateIpAddresses": [a["eni_a_secondary"]]})
        self.snapshot("after-secondary-unassign", [ea, eb], [na])
        self.ec2("delete-unattached-eni-with-eip", "delete_network_interface", {"NetworkInterfaceId": na})
        self.snapshot("after-eni-delete", [ea, eb], [na])
        association = self.disassociate("disassociate-eip-a", ea)
        if association:
            self.ec2("disassociate-repeat", "disassociate_address", {"AssociationId": association})
        self.disassociate("disassociate-eip-b", eb)
        self.ec2("release-eip-b", "release_address", {"AllocationId": eb}, required=True)
        self.ec2("release-eip-b-repeat", "release_address", {"AllocationId": eb})
        self.ec2("describe-eip-b-released", "describe_addresses", {"AllocationIds": [eb]})

    def lifecycle(self):
        a, owned = self.data["aliases"], self.data["owned"]
        image = self.ec2("published-al2023-images", "describe_images", {"Owners": ["amazon"], "Filters": [
            {"Name": "name", "Values": ["al2023-ami-2023*-x86_64"]}, {"Name": "state", "Values": ["available"]},
            {"Name": "root-device-type", "Values": ["ebs"]}, {"Name": "virtualization-type", "Values": ["hvm"]}]}, required=True)
        image = max(image["Images"], key=lambda value: value["CreationDate"])
        launch = self.ec2("launch-one-public-t3-micro", "run_instances", {"ImageId": image["ImageId"],
            "InstanceType": "t3.micro", "MinCount": 1, "MaxCount": 1, "ClientToken": self.data["prefix"],
            "CreditSpecification": {"CpuCredits": "standard"}, "MetadataOptions": {"HttpTokens": "required"},
            "BlockDeviceMappings": [{"DeviceName": image["RootDeviceName"], "Ebs": {"VolumeSize": 8, "VolumeType": "gp3", "DeleteOnTermination": True}}],
            "NetworkInterfaces": [{"DeviceIndex": 0, "SubnetId": owned["subnet"], "AssociatePublicIpAddress": True, "DeleteOnTermination": True}],
            "TagSpecifications": self.tags("instance") + self.tags("volume") + self.tags("network-interface")}, required=True)
        iid = launch["Instances"][0]["InstanceId"]
        instance = self.state("initial-running", iid, "running")
        primary = instance["NetworkInterfaces"][0]["NetworkInterfaceId"]
        self.aliases(instance=iid, instance_primary=primary)
        self.snapshot("ephemeral-initial", [a["eip_a"]], [primary], iid)
        self.ec2("stop-ephemeral", "stop_instances", {"InstanceIds": [iid]}, required=True)
        self.state("ephemeral-stopped", iid, "stopped")
        self.snapshot("ephemeral-stopped", [a["eip_a"]], [primary], iid)
        self.ec2("start-ephemeral", "start_instances", {"InstanceIds": [iid]}, required=True)
        self.state("ephemeral-restarted", iid, "running")
        self.snapshot("ephemeral-restarted", [a["eip_a"]], [primary], iid)
        self.ec2("associate-running-instance", "associate_address", {"AllocationId": a["eip_a"], "InstanceId": iid}, required=True)
        self.snapshot("elastic-replaces-ephemeral", [a["eip_a"]], [primary], iid)
        association = self.disassociate("running-elastic-disassociate", a["eip_a"])
        self.ec2("disassociate-running-repeat", "disassociate_address", {"AssociationId": association})
        self.snapshot("ephemeral-after-disassociate", [a["eip_a"]], [primary], iid)
        self.ec2("associate-elastic-before-stop", "associate_address", {"AllocationId": a["eip_a"], "InstanceId": iid}, required=True)
        self.ec2("stop-elastic", "stop_instances", {"InstanceIds": [iid]}, required=True)
        self.state("elastic-stopped", iid, "stopped")
        self.snapshot("elastic-stopped", [a["eip_a"]], [primary], iid)
        self.disassociate("stopped-elastic-disassociate", a["eip_a"])
        self.ec2("associate-stopped-instance", "associate_address", {"AllocationId": a["eip_a"], "InstanceId": iid}, required=True)
        self.snapshot("stopped-associated", [a["eip_a"]], [primary], iid)
        self.ec2("attach-secondary-to-stopped", "attach_network_interface", {"NetworkInterfaceId": a["eni_b"], "InstanceId": iid, "DeviceIndex": 1}, required=True)
        self.ec2("associate-multiple-eni-instance", "associate_address", {"AllocationId": a["eip_a"], "InstanceId": iid})
        self.associate("associate-stopped-secondary-eni", a["eip_a"], a["eni_b"])
        self.snapshot("stopped-secondary-associated", [a["eip_a"]], [primary, a["eni_b"]], iid)
        self.ec2("delete-attached-stopped-eni", "delete_network_interface", {"NetworkInterfaceId": a["eni_b"]})
        attachment = self.ec2("secondary-attachment", "describe_network_interfaces", {"NetworkInterfaceIds": [a["eni_b"]]}, required=True)["NetworkInterfaces"][0]["Attachment"]["AttachmentId"]
        self.ec2("detach-stopped-secondary-with-eip", "detach_network_interface", {"AttachmentId": attachment}, required=True)
        for attempt in range(45):
            interface = self.ec2("secondary-detached-" + str(attempt), "describe_network_interfaces", {"NetworkInterfaceIds": [a["eni_b"]]}, required=True)["NetworkInterfaces"][0]
            if not interface.get("Attachment"):
                break
            time.sleep(2)
        else:
            raise RuntimeError("Secondary ENI detach deadline")
        self.snapshot("detached-secondary-retains-eip", [a["eip_a"]], [a["eni_b"]], iid)
        self.associate("elastic-back-to-stopped-primary", a["eip_a"], primary)
        self.ec2("start-elastic", "start_instances", {"InstanceIds": [iid]}, required=True)
        self.state("elastic-restarted", iid, "running")
        self.snapshot("elastic-restarted", [a["eip_a"]], [primary], iid)
        self.ec2("terminate-with-elastic", "terminate_instances", {"InstanceIds": [iid]}, required=True)
        self.state("terminal", iid, "terminated")
        self.snapshot("after-termination", [a["eip_a"]], (), iid)

    def run(self):
        signal.alarm(self.args.live_seconds)
        self.setup()
        self.admission()
        self.interfaces()
        self.lifecycle()
        self.data["capture_complete_at"] = now()
        self.save()

    def cleanup(self):
        signal.alarm(600)
        owned = self.data["owned"]
        failures = []
        for iid in owned["instances"]:
            self.ec2("cleanup-terminate-" + iid, "terminate_instances", {"InstanceIds": [iid]})
            self.state("cleanup-terminal-" + iid, iid, "terminated")
        for allocation in owned["allocations"]:
            output = self.ec2("cleanup-address-" + allocation, "describe_addresses", {"AllocationIds": [allocation]})
            for address in output.get("Addresses", []):
                if address.get("AssociationId"):
                    self.ec2("cleanup-disassociate-" + allocation, "disassociate_address", {"AssociationId": address["AssociationId"]})
                self.ec2("cleanup-release-" + allocation, "release_address", {"AllocationId": allocation})
            self.ec2("cleanup-verify-address-" + allocation, "describe_addresses", {"AllocationIds": [allocation]})
            if self.data["calls"][-1]["code"] != "InvalidAllocationID.NotFound":
                failures.append(allocation)
        for interface in owned["interfaces"]:
            for attempt in range(30):
                self.ec2("cleanup-delete-eni-" + interface + "-" + str(attempt), "delete_network_interface", {"NetworkInterfaceId": interface})
                self.ec2("cleanup-verify-eni-" + interface + "-" + str(attempt), "describe_network_interfaces", {"NetworkInterfaceIds": [interface]})
                if self.data["calls"][-1]["code"] == "InvalidNetworkInterfaceID.NotFound":
                    break
                time.sleep(2)
            else:
                failures.append(interface)
        for volume in owned["volumes"]:
            self.ec2("cleanup-verify-root-" + volume, "describe_volumes", {"VolumeIds": [volume]})
            if self.data["calls"][-1]["code"] != "InvalidVolume.NotFound":
                failures.append(volume)
        if owned.get("gateway"):
            self.ec2("cleanup-detach-igw", "detach_internet_gateway", {"InternetGatewayId": owned["gateway"], "VpcId": owned["vpc"]})
            self.ec2("cleanup-delete-igw", "delete_internet_gateway", {"InternetGatewayId": owned["gateway"]})
            self.ec2("cleanup-verify-igw", "describe_internet_gateways", {"InternetGatewayIds": [owned["gateway"]]})
            if self.data["calls"][-1]["code"] != "InvalidInternetGatewayID.NotFound":
                failures.append(owned["gateway"])
        for kind, method, describe, key, missing in (
            ("subnet", "delete_subnet", "describe_subnets", "Subnet", "InvalidSubnetID.NotFound"),
            ("vpc", "delete_vpc", "describe_vpcs", "Vpc", "InvalidVpcID.NotFound")):
            if owned.get(kind):
                self.ec2("cleanup-delete-" + kind, method, {key + "Id": owned[kind]})
                self.ec2("cleanup-verify-" + kind, describe, {key + "Ids": [owned[kind]]})
                if self.data["calls"][-1]["code"] != missing:
                    failures.append(owned[kind])
        self.data["cleanup"] = {"verified_at": now(), "remaining": failures, "exact_owned_absence_verified": not failures,
            "instance_terminal_note": "Terminated instance descriptions and immutable AWS history are retained by AWS, not claimed erased."}
        self.save()
        signal.alarm(0)
        if failures:
            raise RuntimeError("Cleanup incomplete: " + ", ".join(failures))


def summarize(path):
    data = json.loads(path.read_text())
    summary = {"schema": 1, "source_fixture": path.name, "source": "native AWS only", "account": data["account"],
        "region": data["region"], "captured_at": data["captured_at"], "documentation": data["documentation"],
        "aliases": data["aliases"], "bounds": data["bounds"], "cleanup": data["cleanup"], "gaps": data["gaps"],
        "cases": [{key: row[key] for key in ("label", "operation", "input", "code", "error", "output", "request_id") if key in row}
                  for row in data["calls"] if row["operation"] in OPERATIONS],
        "snapshots": data["snapshots"]}
    path.with_name(path.stem + "_handoff.json").write_text(json.dumps(summary, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--account", help="Required for native capture and cleanup")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", type=Path, default=Path(".stackd/probes/ec2/public_addresses.json"))
    parser.add_argument("--live-seconds", type=int, default=1800)
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--summarize-only", action="store_true")
    args = parser.parse_args()
    if not 60 <= args.live_seconds <= 1800:
        parser.error("experiment must be 60..1800 seconds, reserving bounded cleanup")
    if args.summarize_only:
        summarize(args.output)
        return
    if not args.account:
        parser.error("--account is required for native AWS operations")
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(sig, interrupt)
    capture = PublicAddressCapture(args)
    try:
        if not args.cleanup_only:
            capture.run()
    except BaseException as error:
        capture.data["failure"] = {"type": type(error).__name__, "message": str(error), "at": now()}
        capture.save()
        raise
    finally:
        try:
            capture.cleanup()
        finally:
            summarize(args.output)


if __name__ == "__main__":
    main()
