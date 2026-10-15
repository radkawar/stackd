"""Optional Terraform EBS controls with a real, prepared QEMU guest.

The input raw disk is opened read-only and imported through EBS Direct. Nothing
here installs host adapters or modifies an image. See ebs-limits.json for the
exact prerequisites, runnable command and deliberately unverified remainder.
"""
import base64
import contextlib
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from local import client, environment, expect_missing, local_endpoint, require


BLOCK_SIZE = 512 * 1024
MARKER_OFFSET = 4 * 1024 * 1024
ISOLATION_OFFSET = 8 * 1024 * 1024


class StrictPlanFailure(RuntimeError):
    """Keep a proved no-diff detailed-exit failure terminal after native reopen."""

    def __init__(self, checks):
        super().__init__("Strict EBS no-change plan returned2 despite a saved no-diff plan; failure retained")
        self.checks = checks


# This guest process never remembers written bytes. Each independent operation
# discovers the current hardware serial and opens the exact unmounted disk anew.
GUEST = r'''import base64, fcntl, hmac, json, os, re, stat, struct
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
TOKEN = __TOKEN__

def disk(volume):
    if not re.fullmatch(r"vol-[0-9a-f]{8,17}", volume):
        raise ValueError("invalid owned volume ID")
    found = []
    for block in Path("/sys/class/block").glob("nvme*n*"):
        match = re.fullmatch(r"(nvme[0-9]+)n[0-9]+", block.name)
        if not match:
            continue
        serial = Path("/sys/class/nvme", match[1], "serial").read_text().strip()
        if serial == volume.replace("-", ""):
            found.append((block, serial))
    if not found:
        raise FileNotFoundError("owned NVMe serial is absent")
    if len(found) != 1:
        raise ValueError("owned NVMe serial is ambiguous")
    block, serial = found[0]
    target = block.resolve()
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        mounted = Path("/sys/dev/block", line.split()[2]).resolve()
        if mounted == target or target in mounted.parents:
            raise ValueError("refusing a mounted disk or its mounted partitions")
    path = Path("/dev", block.name)
    if not stat.S_ISBLK(path.stat().st_mode):
        raise ValueError("NVMe path is not a real block device")
    return path, serial

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_POST(self):
        if not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + TOKEN):
            self.send_error(401)
            return
        try:
            if not self.path.startswith("/v1/") or "/" in self.path[4:]:
                raise ValueError("invalid consumer path")
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 16384:
                raise ValueError("invalid bounded request size")
            request = json.loads(self.rfile.read(size))
            path, serial = disk(self.path[4:])
            operation = request["op"]
            fd = os.open(path, os.O_RDWR | os.O_SYNC if operation == "write" else os.O_RDONLY)
            try:
                capacity = struct.unpack("Q", fcntl.ioctl(fd, 0x80081272, bytes(8)))[0]
                result = {"serial": serial, "size": capacity}
                if operation in ("write", "read"):
                    offset = request["offset"]
                    length = request.get("length", 0)
                    data = base64.b64decode(request["data"], validate=True) if operation == "write" else None
                    if data is not None:
                        length = len(data)
                    if not isinstance(offset, int) or not isinstance(length, int) or not 0 < length <= 4096 or offset < 0 or offset + length > capacity:
                        raise ValueError("invalid bounded disk range")
                    if operation == "write":
                        if os.pwrite(fd, data, offset) != length:
                            raise OSError("short native write")
                        os.fsync(fd)
                        fcntl.ioctl(fd, 0x1261)  # BLKFLSBUF: flush/invalidate guest block cache.
                    else:
                        data = os.pread(fd, length, offset)
                        if len(data) != length:
                            raise OSError("short native read")
                        result["data"] = base64.b64encode(data).decode()
                elif operation != "stat":
                    raise ValueError("unknown disk operation")
            finally:
                os.close(fd)
            body = json.dumps(result).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except FileNotFoundError:
            self.send_error(404, "owned NVMe serial absent")
        except ValueError as error:
            self.send_error(409, str(error))
        except Exception as error:
            self.send_error(500, str(error))
HTTPServer(("0.0.0.0", 8765), Handler).serve_forever()
'''


def run(args, root: Path, endpoint: str, terraform, variables: dict, stages: list):
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    image = Path(args.guest_image).resolve() if getattr(args, "guest_image", None) else None
    boot_mode = getattr(args, "guest_boot_mode", "legacy-bios")
    require(image is not None and image.is_file(),
            "EBS requires --guest-image: prepared raw Linux x86_64 HVM full disk with a matching bootloader, Python3, cloud-init EC2, DHCP, NVMe and virtio-net")
    require(boot_mode in ("legacy-bios", "uefi"), "Select --guest-boot-mode legacy-bios or uefi")
    firmware_args = ("ec2_bios",) if boot_mode == "legacy-bios" else ("ec2_uefi_code", "ec2_uefi_vars")
    for argument in firmware_args:
        firmware = getattr(args, argument, None)
        require(firmware is not None and Path(firmware).is_file(),
                "EBS requires existing matching --" + argument.replace("_", "-") + " firmware; no firmware/image fallback")
    missing = [name for name in ("qemu-system-x86_64", "qemu-img", "qemu-nbd", "qemu-io", "dnsmasq", "dhcp_release") if shutil.which(name) is None]
    require(not missing, "Install the native EC2 adapter prerequisites first: " + ", ".join(missing))
    require(os.access("/dev/kvm", os.R_OK | os.W_OK) and os.access("/dev/net/tun", os.R_OK | os.W_OK),
            "EBS requires controller read/write /dev/kvm and /dev/net/tun, Linux x86_64 systemd/cgroup-v2, local rootful Docker and the installed pinned network toolkit; see docs/runtime-vms.md")
    info = subprocess.run(["qemu-img", "info", "--output=json", str(image)],
                          env=environment(), capture_output=True, text=True, check=True)
    require(json.loads(info.stdout)["format"] == "raw", "--guest-image must already be raw; convert a separate copy, never the input file")
    require(image.stat().st_size > 0, "The prepared raw guest image is empty")
    shutil.copyfile(Path(__file__).with_name("ebs.tf"), root / "main.tf")
    token = secrets.token_hex(32)
    script = GUEST.replace("__TOKEN__", repr(token))
    cloud_config = {
        "write_files": [
            {"path": "/usr/local/sbin/stackd-ebs-consumer.py", "permissions": "0700", "content": script},
            {"path": "/etc/systemd/system/stackd-ebs-consumer.service", "permissions": "0600", "content":
             "[Unit]\nAfter=network.target\n[Service]\nExecStart=/usr/bin/python3 /usr/local/sbin/stackd-ebs-consumer.py\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n"}],
        "runcmd": [["systemctl", "daemon-reload"], ["systemctl", "enable", "--now", "stackd-ebs-consumer.service"]],
    }
    values = {key: variables[key] for key in ("name", "region", "account_id")}
    share_account = "123456789012" if values["account_id"] != "123456789012" else "210987654321"
    values.update(endpoint=local_endpoint(endpoint), image_id="", user_data="#cloud-config\n" + json.dumps(cloud_config),
                  vpc_cidr=getattr(args, "ebs_vpc_cidr", None) or "10.194.29.0/24",
                  instance_type=getattr(args, "guest_instance_type", "t3.small"),
                  source_size=1, source_attached=True, snapshot_enabled=False, restore_enabled=False,
                  permission_enabled=True, share_account=share_account, reader_allowed=True, revision="initial")
    network = ipaddress.ip_network(values["vpc_cidr"], strict=True)
    require(network.version == 4 and network.prefixlen == 24 and network.is_private,
            "EBS guest needs an explicitly owned, host/VPN/Docker-nonoverlapping private IPv4 /24")
    active_endpoint = values["endpoint"]
    outputs = None
    initialized = False
    destroyed = False
    boot_snapshot = None
    boot_image = None
    input_digest = None
    owned_ids = {}
    clients = {}
    command_number = 0
    verification_count = 0
    initial_plan_failure = None
    prefix = b"stackd native EBS cold bytes\x00\xff"
    marker = prefix + secrets.token_bytes(4096 - len(prefix))
    changed = b"stackd native EBS source changed\x00\xff" + secrets.token_bytes(512)
    isolated = b"stackd native EBS restored only\x00\xff" + secrets.token_bytes(512)

    def private_write(path, data):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        path.chmod(0o600)

    def save():
        private_write(root / "local.auto.tfvars.json", json.dumps(values).encode())

    def remember():
        private_write(root / "owned.json", json.dumps({"boot_snapshot": boot_snapshot, "boot_image": boot_image,
                      "image_sha256": input_digest, "terraform_ids": owned_ids}, indent=2).encode())

    def stage(name):
        stages.append({"stage": "ebs-" + name, "status": "passed"})

    def api(service):
        if service not in clients:
            clients[service] = client(service, active_endpoint)
        return clients[service]

    def tf(*command, check=True):
        nonlocal command_number
        command_number += 1
        result = terraform(list(command), root, check=False)
        private_write(root / f"terraform-{command_number:03d}-{command[0]}.log",
                      (result.stdout + "\n--- stderr ---\n" + result.stderr).encode())
        if check:
            require(result.returncode == 0,
                    f"EBS Terraform {command[0]} failed; inspect private command log {command_number:03d} in {root}")
        return result

    @contextlib.contextmanager
    def ticking():
        stopped, errors = threading.Event(), []
        def tick():
            http = build_opener(ProxyHandler({}))
            while not stopped.wait(0.5):
                try:
                    request = Request(active_endpoint + "/_stackd/clock", data=b'{"advance":"1s"}',
                                      headers={"Content-Type": "application/json"})
                    with http.open(request, timeout=30) as response:
                        require(response.status == 200, "EBS manual-clock advance failed")
                        response.read()
                except Exception as error:
                    errors.append(error)
                    return
        worker = threading.Thread(target=tick, name="ebs-service-clock", daemon=True)
        worker.start()
        try:
            yield
            require(not errors, "EBS provider-wait clock failed: " + str(errors))
        finally:
            stopped.set()
            worker.join(timeout=35)
            require(not worker.is_alive(), "EBS service-clock worker did not stop")

    def poll(observation, accepted, message, timeout=600):
        deadline = time.monotonic() + timeout
        while True:
            result = observation()
            if accepted(result):
                return result
            require(time.monotonic() < deadline, message)
            time.sleep(0.5)

    def use_endpoint(replacement):
        nonlocal active_endpoint
        if replacement is not None:
            active_endpoint = local_endpoint(replacement)
            values["endpoint"] = active_endpoint
            clients.clear()
            save()

    def refresh_outputs():
        nonlocal outputs
        outputs = json.loads(tf("output", "-json", "ebs").stdout)
        for key in ("source_id", "restored_id", "snapshot_id", "instance_id", "root_volume_id", "vpc_id", "subnet_id", "security_group_id"):
            if outputs.get(key):
                owned_ids[key] = outputs[key]
        remember()
        require(ipaddress.ip_address(outputs["guest_ip"]) in network, "Guest endpoint escaped the exact owned subnet")
        return outputs

    def apply():
        save()
        tf("apply", "-input=false", "-auto-approve", "-parallelism=1")
        refresh_outputs()

    def guest(volume, operation="stat", **data):
        body = json.dumps({"op": operation, **data}).encode()
        request = Request(f"http://{outputs['guest_ip']}:8765/v1/{volume}", data=body,
                          headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
        with build_opener(ProxyHandler({})).open(request, timeout=10) as response:
            result = json.load(response)
        require(result["serial"] == volume.replace("-", ""), "Guest read a disk with a different NVMe hardware identity")
        return result

    def attached(volume, size):
        def observe():
            try:
                return guest(volume)
            except HTTPError as error:
                if error.code != 404:
                    raise
            except (URLError, TimeoutError, ConnectionError):
                pass
            return None
        return poll(observe, lambda result: result is not None and result["size"] == size << 30,
                    "Prepared guest did not expose the exact owned NVMe serial and actual requested byte capacity; inspect image, firmware, native logs and host adapter prerequisites")

    def absent(volume):
        def observe():
            try:
                guest(volume)
                return False
            except HTTPError as error:
                require(error.code == 404, "Guest failed instead of observing detached NVMe disappearance")
                return True
        poll(observe, bool, "Detached volume remained a real guest NVMe device", timeout=90)

    def write_marker(volume, data, offset=MARKER_OFFSET):
        guest(volume, "write", offset=offset, data=base64.b64encode(data).decode())

    def read_marker(volume, expected, offset=MARKER_OFFSET):
        actual = guest(volume, "read", offset=offset, length=len(expected))
        payload = base64.b64decode(actual["data"], validate=True)
        require(payload == expected, "Independent native block read changed binary marker bytes")
        return {"sha256": hashlib.sha256(payload).hexdigest(), "length": len(payload),
                "offset": offset, "serial": actual["serial"]}

    def snapshot_block(ebs_client=None):
        ebs_client = ebs_client or api("ebs")
        index = MARKER_OFFSET // BLOCK_SIZE
        listed = ebs_client.list_snapshot_blocks(SnapshotId=outputs["snapshot_id"], StartingBlockIndex=index, MaxResults=100)
        require(listed["BlockSize"] == BLOCK_SIZE, "Unexpected EBS Direct block size")
        blocks = [item for item in listed["Blocks"] if item["BlockIndex"] == index]
        require(len(blocks) == 1, "Cold snapshot did not retain the guest's nonzero binary block")
        return {"SnapshotId": outputs["snapshot_id"], "BlockIndex": index, "BlockToken": blocks[0]["BlockToken"]}

    def read_snapshot(ebs_client=None, request=None):
        ebs_client = ebs_client or api("ebs")
        result = ebs_client.get_snapshot_block(**(request or snapshot_block(ebs_client)))
        stream = result["BlockData"]
        try:
            data = stream.read()
        finally:
            stream.close()
        require(len(data) == BLOCK_SIZE and result["DataLength"] == BLOCK_SIZE and result["ChecksumAlgorithm"] == "SHA256"
                and base64.b64encode(hashlib.sha256(data).digest()).decode() == result["Checksum"],
                "EBS Direct immutable snapshot block length/checksum changed")
        require(data[:len(marker)] == marker, "Cold snapshot captured metadata or zeroes instead of actual guest-written binary bytes")
        return {"block_sha256": hashlib.sha256(data).hexdigest(), "block_length": len(data),
                "marker_sha256": hashlib.sha256(data[:len(marker)]).hexdigest(), "marker_length": len(marker)}

    def no_change(phase):
        failures = []
        for label, options in (("refresh", ("-refresh-only",)), ("ordinary", ())):
            plan = root / ("strict-" + phase + "-" + label + ".tfplan")
            command = ("plan", "-input=false", "-detailed-exitcode", "-out=" + str(plan), *options)
            result = tf(*command, check=False)
            if plan.is_file():
                plan.chmod(0o600)
            if result.returncode == 0:
                continue
            require(result.returncode == 2 and "No changes." in result.stdout
                    and "found no differences." in result.stdout,
                    "EBS refresh or ordinary plan contains drift or failed; no ignored changes are permitted")
            saved = json.loads(tf("show", "-json", str(plan)).stdout)
            require(all(entry["change"]["actions"] == ["no-op"]
                        for group in ("resource_changes", "resource_drift")
                        for entry in saved.get(group, []))
                    and all(entry["actions"] == ["no-op"] for entry in saved.get("output_changes", {}).values()),
                    "EBS saved no-change plan contains a real resource or output difference")
            failures.append({"command": list(command), "returncode": result.returncode, "plan": plan.name})
        if failures:
            raise StrictPlanFailure(failures)

    def import_resource(address, identity):
        state = root / "terraform.tfstate"
        backup = root / "terraform.tfstate.backup"
        previous = state.read_bytes()
        previous_backup = backup.read_bytes() if backup.exists() else None
        private_write(root / ("before-import-" + address.replace(".", "-").replace("[", "-").replace("]", "") + ".json"), previous)
        try:
            tf("state", "rm", address)
            tf("import", "-input=false", address, identity)
        except BaseException:
            # Restore all ownership before the ordinary destroy path can run.
            private_write(state, previous)
            if previous_backup is not None:
                private_write(backup, previous_backup)
            elif backup.exists():
                backup.unlink()
            raise

    def verify(endpoint=None):
        nonlocal verification_count
        verification_count += 1
        phase = "initial" if verification_count == 1 else "reopen"
        use_endpoint(endpoint)
        with ticking():
            refresh_outputs()
            instance = api("ec2").describe_instances(InstanceIds=[outputs["instance_id"]])["Reservations"][0]["Instances"][0]
            require(instance["ImageId"] == boot_image and instance["PrivateIpAddress"] == outputs["guest_ip"],
                    "Reopened instance no longer owns the imported image and exact native consumer endpoint")
            for key in ("source_id", "restored_id"):
                attached(outputs[key], 2)
            source_bytes = read_marker(outputs["source_id"], changed)
            restored_bytes = read_marker(outputs["restored_id"], marker)
            source_isolation = read_marker(outputs["source_id"], bytes(len(isolated)), ISOLATION_OFFSET)
            restored_isolation = read_marker(outputs["restored_id"], isolated, ISOLATION_OFFSET)
            snapshot_bytes = read_snapshot()
            volumes = api("ec2").describe_volumes(VolumeIds=[outputs["source_id"], outputs["restored_id"]])["Volumes"]
            require({v["VolumeId"] for v in volumes} == {outputs["source_id"], outputs["restored_id"]}
                    and all(v["Size"] == 2 and v["VolumeType"] == "gp3" and v["Iops"] == 3000 and v["Throughput"] == 125 for v in volumes),
                    "Current volume authority changed native requested configuration")
            restored = next(v for v in volumes if v["VolumeId"] == outputs["restored_id"])
            require(restored["SnapshotId"] == outputs["snapshot_id"], "Restored volume lost its immutable source snapshot ID")
            snapshot = api("ec2").describe_snapshots(SnapshotIds=[outputs["snapshot_id"]])["Snapshots"][0]
            require(snapshot["VolumeId"] == outputs["source_id"] and snapshot["VolumeSize"] == 2 and snapshot["State"] == "completed",
                    "Cold snapshot lost its immutable source-volume identity/size")
            permissions = api("ec2").describe_snapshot_attribute(SnapshotId=outputs["snapshot_id"], Attribute="createVolumePermission")["CreateVolumePermissions"]
            require(permissions == [{"UserId": share_account}], "Snapshot permission grant changed or became public")
            require(outputs["source_data_id"] == outputs["source_id"] and outputs["source_data_size"] == 2
                    and set(outputs["owned_volume_ids"]) == {outputs["source_id"], outputs["restored_id"]}
                    and outputs["snapshot_source_id"] == outputs["source_id"] and outputs["snapshot_size"] == 2
                    and outputs["snapshot_data_ids"] == [outputs["snapshot_id"]], "Terraform EBS data sources disagreed with the owned native resources")
            with image.open("rb") as source:
                require(hashlib.file_digest(source, "sha256").hexdigest() == input_digest, "Prepared guest source file changed")
        private_write(root / ("native-evidence-" + phase + ".json"), json.dumps({
            "phase": phase, "image_sha256": input_digest, "image_digest_unchanged": True,
            "owned_ids": owned_ids, "source": source_bytes, "restored": restored_bytes,
            "source_isolation_zeroes": source_isolation, "restored_private_bytes": restored_isolation,
            "cold_snapshot_direct": snapshot_bytes, "source_and_restored_size_gib": 2,
        }, sort_keys=True, indent=2).encode())
        stage("native-persistence-isolation-current-state-" + phase)
        try:
            no_change(phase)
        except StrictPlanFailure as error:
            stages.append({"stage": "ebs-strict-no-change-" + phase, "status": "failed", "checks": error.checks})
            raise
        stage("strict-no-change-" + phase)

    def verify_reopen(endpoint=None):
        verify(endpoint)
        if initial_plan_failure is not None:
            raise initial_plan_failure

    def cleanup(endpoint=None):
        nonlocal destroyed, boot_image, boot_snapshot
        use_endpoint(endpoint)
        if destroyed:
            return
        failures = []
        state_path = root / "terraform.tfstate"
        if state_path.exists():
            state_ids = {
                ("aws_ebs_volume", "source"): "source_id",
                ("aws_ebs_volume", "restored"): "restored_id",
                ("aws_ebs_snapshot", "cold"): "snapshot_id",
                ("aws_instance", "guest"): "instance_id",
                ("aws_vpc", "guest"): "vpc_id",
                ("aws_subnet", "guest"): "subnet_id",
                ("aws_security_group", "guest"): "security_group_id",
            }
            for resource in json.loads(state_path.read_text()).get("resources", []):
                key = state_ids.get((resource["type"], resource["name"]))
                if resource.get("mode") != "managed" or key is None:
                    continue
                for instance in resource.get("instances", []):
                    attributes = instance.get("attributes", {})
                    if attributes.get("id"):
                        owned_ids[key] = attributes["id"]
                    if key == "instance_id":
                        for disk in attributes.get("root_block_device", []):
                            if disk.get("volume_id"):
                                owned_ids["root_volume_id"] = disk["volume_id"]
            remember()
        def volume_deleted(volume_id):
            try:
                api("ec2").describe_volumes(VolumeIds=[volume_id])
                return False
            except ClientError as error:
                require(error.response["Error"]["Code"] == "InvalidVolume.NotFound",
                        "Unexpected owned-volume cleanup failure: " + str(error))
                return True
        with ticking():
            if initialized:
                result = tf("destroy", "-input=false", "-auto-approve", "-parallelism=1", check=False)
                if result.returncode != 0:
                    failures.append("Owned EBS Terraform destroy failed; inspect private Terraform logs/state and retain native state")
            if boot_image is not None:
                try:
                    api("ec2").deregister_image(ImageId=boot_image)
                    require(not api("ec2").describe_images(ImageIds=[boot_image])["Images"],
                            "Deregistered bootstrap AMI remained launchable/discoverable")
                    boot_image = None
                    remember()
                except Exception as error:
                    failures.append("Owned bootstrap AMI cleanup: " + str(error))
            if boot_snapshot is not None:
                try:
                    api("ec2").delete_snapshot(SnapshotId=boot_snapshot)
                    expect_missing(api("ec2").describe_snapshots, {"InvalidSnapshot.NotFound"}, SnapshotIds=[boot_snapshot])
                    boot_snapshot = None
                    remember()
                except Exception as error:
                    failures.append("Owned bootstrap snapshot cleanup: " + str(error))
            if not failures:
                for key in ("source_id", "restored_id", "root_volume_id"):
                    if owned_ids.get(key):
                        poll(lambda: volume_deleted(owned_ids[key]), bool, "Owned native volume deletion did not complete", timeout=90)
                        arn = f"arn:aws:ec2:{values['region']}:{values['account_id']}:volume/{owned_ids[key]}"
                        disk = root.parent / "ec2" / "volumes" / (hashlib.sha256(arn.encode()).hexdigest() + ".qcow2")
                        require(not disk.exists(), "Deleted owned EBS volume retained its native qcow2 disk")
                if owned_ids.get("snapshot_id"):
                    expect_missing(api("ec2").describe_snapshots, {"InvalidSnapshot.NotFound"}, SnapshotIds=[owned_ids["snapshot_id"]])
                for key, operation, argument, code in (
                    ("subnet_id", "describe_subnets", "SubnetIds", "InvalidSubnetID.NotFound"),
                    ("security_group_id", "describe_security_groups", "GroupIds", "InvalidGroup.NotFound"),
                    ("vpc_id", "describe_vpcs", "VpcIds", "InvalidVpcID.NotFound")):
                    if owned_ids.get(key):
                        expect_missing(getattr(api("ec2"), operation), {code}, **{argument: [owned_ids[key]]})
                if owned_ids.get("instance_id"):
                    row = api("ec2").describe_instances(InstanceIds=[owned_ids["instance_id"]])["Reservations"][0]["Instances"][0]
                    require(row["State"]["Name"] == "terminated", "Owned native guest survived Terraform destroy")
                    arn = f"arn:aws:ec2:{values['region']}:{values['account_id']}:instance/{owned_ids['instance_id']}"
                    directory = root.parent / "ec2" / ("vm-" + hashlib.sha256(arn.encode()).hexdigest()[:24])
                    require(not directory.exists(), "Terminated owned guest retained native QMP/process/firmware artifacts")
        require(not failures, "; ".join(failures))
        destroyed = True
        stage("destroy-native-guest-volumes-snapshot-network-and-bootstrap")

    try:
        save()
        tf("init", "-input=false")
        initialized = True
        with ticking():
            size_gib = (image.stat().st_size + (1 << 30) - 1) >> 30
            started = api("ebs").start_snapshot(VolumeSize=size_gib, Description=values["name"] + " owned raw guest bootstrap")
            boot_snapshot = started["SnapshotId"]
            remember()
            count, digest = 0, hashlib.sha256()
            with image.open("rb") as source:
                index = 0
                while raw := source.read(BLOCK_SIZE):
                    digest.update(raw)
                    block = raw.ljust(BLOCK_SIZE, b"\0")
                    if block.strip(b"\0"):
                        api("ebs").put_snapshot_block(SnapshotId=boot_snapshot, BlockIndex=index, BlockData=block,
                            DataLength=BLOCK_SIZE, ChecksumAlgorithm="SHA256",
                            Checksum=base64.b64encode(hashlib.sha256(block).digest()).decode())
                        count += 1
                    index += 1
            require(count > 0, "Guest raw image contains no real boot/image bytes")
            input_digest = digest.hexdigest()
            api("ebs").complete_snapshot(SnapshotId=boot_snapshot, ChangedBlocksCount=count)
            def boot_state():
                row = api("ec2").describe_snapshots(SnapshotIds=[boot_snapshot])["Snapshots"][0]
                require(row["State"] != "error", "Owned raw-image bootstrap snapshot failed")
                return row["State"]
            poll(boot_state, lambda state: state == "completed", "Owned raw-image bootstrap did not complete")
            boot_image = api("ec2").register_image(Name=values["name"] + "-ebs-guest", Architecture="x86_64",
                RootDeviceName="/dev/sda1", VirtualizationType="hvm", BootMode=boot_mode, EnaSupport=True,
                BlockDeviceMappings=[{"DeviceName": "/dev/sda1", "Ebs": {"SnapshotId": boot_snapshot,
                    "VolumeSize": max(8, size_gib), "VolumeType": "gp3", "DeleteOnTermination": True}}])["ImageId"]
            remember()
            values["image_id"] = boot_image
            apply()
            attached(outputs["source_id"], 1)
            write_marker(outputs["source_id"], marker)
            read_marker(outputs["source_id"], marker)
            stage("prepared-image-import-native-attach-independent-binary-read")
            values["source_attached"] = False
            apply()
            absent(outputs["source_id"])
            volume = api("ec2").describe_volumes(VolumeIds=[outputs["source_id"]])["Volumes"][0]
            require(volume["State"] == "available" and not volume.get("Attachments"), "Cold native disk still has an attachment owner")
            values.update(source_size=2, revision="updated")
            apply()
            values["source_attached"] = True
            apply()
            attached(outputs["source_id"], 2)
            read_marker(outputs["source_id"], marker)
            stage("detached-native-virtual-disk-resize-and-persistent-reattach")
            values["source_attached"] = False
            apply()
            absent(outputs["source_id"])
            values["snapshot_enabled"] = True
            apply()
            read_snapshot()
            values.update(restore_enabled=True, source_attached=True)
            apply()
            attached(outputs["source_id"], 2)
            attached(outputs["restored_id"], 2)
            read_marker(outputs["restored_id"], marker)
            write_marker(outputs["source_id"], changed)
            read_marker(outputs["source_id"], changed)
            read_marker(outputs["restored_id"], marker)
            write_marker(outputs["restored_id"], isolated, ISOLATION_OFFSET)
            read_marker(outputs["restored_id"], isolated, ISOLATION_OFFSET)
            read_marker(outputs["source_id"], bytes(len(isolated)), ISOLATION_OFFSET)
            read_snapshot()
            stage("cold-snapshot-direct-bytes-restore-and-two-way-write-isolation")
            values["permission_enabled"] = False
            apply()
            require(not api("ec2").describe_snapshot_attribute(SnapshotId=outputs["snapshot_id"], Attribute="createVolumePermission")["CreateVolumePermissions"],
                    "Terraform permission destroy left an effective snapshot share")
            values["permission_enabled"] = True
            apply()
            stage("snapshot-private-permission-grant-revoke-regrant")
            reader = boto3.Session(aws_access_key_id=outputs["reader_key"], aws_secret_access_key=outputs["reader_secret"],
                                   region_name=values["region"])
            options = dict(endpoint_url=active_endpoint, config=Config(connect_timeout=3, read_timeout=30, proxies={}, retries={"max_attempts": 0}))
            reader_ebs, reader_ec2 = (reader.client(service, **options) for service in ("ebs", "ec2"))
            old_token = snapshot_block(reader_ebs)
            read_snapshot(reader_ebs, old_token)
            require(reader_ec2.describe_volumes(VolumeIds=[outputs["source_id"]])["Volumes"][0]["VolumeId"] == outputs["source_id"], "Current EC2 describe permission did not work")
            values["reader_allowed"] = False
            apply()
            expect_missing(reader_ebs.get_snapshot_block, {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}, **old_token)
            expect_missing(reader_ec2.describe_volumes, {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}, VolumeIds=[outputs["source_id"]])
            values["reader_allowed"] = True
            apply()
            read_snapshot(reader_ebs)
            stage("current-iam-revocation-rejects-prior-block-token")
            for address, identity in (
                ("aws_ebs_volume.source", outputs["source_id"]),
                ("aws_ebs_volume.restored[0]", outputs["restored_id"]),
                ("aws_ebs_snapshot.cold[0]", outputs["snapshot_id"]),
                ("aws_volume_attachment.source[0]", f"/dev/sdf:{outputs['source_id']}:{outputs['instance_id']}"),
                ("aws_volume_attachment.restored[0]", f"/dev/sdg:{outputs['restored_id']}:{outputs['instance_id']}")):
                import_resource(address, identity)
            stage("private-state-backed-volume-snapshot-attachment-import")
        try:
            verify()
        except StrictPlanFailure as error:
            # Only the proved saved no-diff/exit2 case may proceed to an
            # independent native reopen. Every other behavior error tears down.
            initial_plan_failure = error
        return verify_reopen, cleanup
    except BaseException as error:
        try:
            cleanup()
        except BaseException as cleanup_error:
            raise RuntimeError(f"EBS failed and owned teardown also failed: {cleanup_error}; retain {root}") from error
        raise
