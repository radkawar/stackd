"""Consume Terraform-managed Valkey through verified TLS and native ACLs."""

import errno
import ipaddress
import json
import socket
from datetime import datetime
from urllib.request import Request, urlopen
import time

import redis
from botocore.exceptions import ClientError

from common import (VALKEY_IMAGE, client, command, delete_unprivileged, denied, inspect_image,
                    password, require, tls, unprivileged)


def prepare(args, root):
    inspect_image(args, VALKEY_IMAGE)
    inspect_image(args, "nicolaka/netshoot@sha256:47b907d662d139d1e2f22bfe14f4efca1e3f1feed283572f47c970c780c03b61")
    (root / "docker-host").write_text(args.docker_host)
    cert, key = tls(root)
    return ["-docker-host", args.docker_host, "-valkey-runtime",
            "-valkey-tls-cert", str(cert), "-valkey-tls-key", str(key)]


def connection(outputs, root, wrong=False, *, anonymous=False):
    address = ipaddress.ip_address(outputs["address"])
    require(address.version == 4 and address.is_private and not address.is_loopback and int(outputs["port"]) == 6379,
            "Native cache endpoint is not its actual reserved IPv4 address on configured6379")
    return redis.Redis(host=outputs["address"], port=int(outputs["port"]),
                       username=None if anonymous else outputs["username"],
                       password=None if anonymous else ("incorrect-local-password" if wrong else password(root)), ssl=True,
                       ssl_ca_certs=str(root / "local.crt"), ssl_cert_reqs="required", ssl_check_hostname=True,
                       socket_connect_timeout=5, socket_timeout=5)


def consume(endpoint, outputs, root, revision, persisted):
    cache = client("elasticache", endpoint)
    deadline = time.monotonic() + 180
    while True:
        group = cache.describe_replication_groups(ReplicationGroupId=outputs["name"])["ReplicationGroups"][0]
        if group["Status"] == "available":
            break
        require(time.monotonic() < deadline, f"Native cache update did not finish: {group}")
        time.sleep(0.5)
    require(group["TransitEncryptionEnabled"] and not group["AtRestEncryptionEnabled"],
            "Unexpected security effect in the native cache description")
    require(outputs["address"] == outputs["node_address"] and outputs["reader_address"] == outputs["reader_node_address"],
            "Group primary/reader endpoint differs from its actual datasource node/port pair")
    native = connection(outputs, root)
    try:
        require(native.ping(), "Native Valkey PING failed")
        key = "fixture:retained"
        previous_file = root / "cache-value"
        previous = previous_file.read_bytes() if persisted else None
        if persisted:
            require(native.get(key) == previous, "Native bytes did not survive update/reopen")
        value = b"Terraform native Valkey\x00\xff:" + revision.encode()
        require(native.set(key, value) and native.get(key) == value, "Native binary SET/GET changed bytes")
        previous_file.write_bytes(value)
        policy = "noeviction" if revision == "v1" else "allkeys-lru"
        require(native.info("memory")["maxmemory_policy"] == policy, "Terraform parameter did not affect the real engine")
        for action in (lambda: native.get("outside-fixture"), lambda: native.execute_command("CONFIG", "GET", "maxmemory-policy")):
            try:
                action()
            except redis.exceptions.NoPermissionError:
                pass
            else:
                raise RuntimeError("Native key/administration ACL did not deny the consumer")
    finally:
        native.close()
    wrong = connection(outputs, root, wrong=True)
    try:
        try:
            wrong.ping()
        except redis.exceptions.AuthenticationError:
            pass
        else:
            raise RuntimeError("Native cache accepted the wrong password")
    finally:
        wrong.close()
    for label, rejected in (
        ("disabled default", connection(dict(outputs, username="default"), root)),
        ("unauthenticated", connection(outputs, root, anonymous=True)),
    ):
        try:
            try:
                rejected.ping()
            except redis.exceptions.AuthenticationError:
                pass
            else:
                raise RuntimeError(f"Native cache accepted {label} access")
        finally:
            rejected.close()
    reader = connection(dict(outputs, address=outputs["reader_address"], port=outputs["reader_port"]), root)
    try:
        require(outputs["reader_address"] != outputs["address"] and int(outputs["reader_port"]) == 6379,
                "Reader substituted the primary attachment or drifted from configured6379")
        deadline = time.monotonic() + 10
        while reader.get("fixture:retained") != value:
            require(time.monotonic() < deadline, "Actual native replica did not receive the binary primary value")
            time.sleep(0.1)
        try:
            reader.set("fixture:retained", b"forbidden-replica-write")
        except redis.exceptions.ReadOnlyError:
            pass
        else:
            raise RuntimeError("Native reader accepted a write instead of being an actual read-only replica")
    finally:
        reader.close()
    unauthorized, owned = unprivileged("elasticache", endpoint, root)
    try:
        denied(lambda: unauthorized.describe_replication_groups(ReplicationGroupId=outputs["name"]))
    finally:
        delete_unprivileged(owned)
    members = [":".join(outputs["arn"].split(":")[:5])+":cluster:"+name for name in group["MemberClusters"]]
    require(len(members) == 2 and len(set(members)) == 2, "Cache tag checks did not select actual distinct members")
    propagation = []
    for member in members:
        tags = cache.list_tags_for_resource(ResourceName=member)["TagList"]
        require({tag["Key"]: tag["Value"] for tag in tags}.get("Revision") == revision,
                "Actual member did not expose its replication group's Terraform revision tag")
        propagation.append({"stage": "terraform-revision", "member": member, "tags": tags})
    cache.add_tags_to_resource(ResourceName=outputs["arn"], Tags=[{"Key": "FixturePropagation", "Value": revision}])
    try:
        for member in members:
            tags = cache.list_tags_for_resource(ResourceName=member)["TagList"]
            require({tag["Key"]: tag["Value"] for tag in tags}.get("FixturePropagation") == revision,
                    "Signed group tag update did not propagate to actual member")
            propagation.append({"stage": "added", "member": member, "tags": tags})
    finally:
        cache.remove_tags_from_resource(ResourceName=outputs["arn"], TagKeys=["FixturePropagation"])
    for member in members:
        tags = cache.list_tags_for_resource(ResourceName=member)["TagList"]
        require("FixturePropagation" not in {tag["Key"] for tag in tags},
                "Signed group tag removal did not propagate to actual member")
        propagation.append({"stage": "removed", "member": member, "tags": tags})
    (root / f"cache-tags-{revision}-{'reopen' if persisted else 'initial'}.json").write_text(json.dumps(propagation, indent=2))
    placement_evidence(endpoint, outputs, root)
    if revision == "v1" and not persisted:
        role = role_deletion(endpoint, "FAILED")
        (root / "cache-live-role-denial.json").write_text(json.dumps(role, indent=2))
        policy_quarantine(endpoint, outputs, root, dhcp=False)
        policy_quarantine(endpoint, outputs, root, dhcp=True)
    print(f"Verified {revision}: real TLS Valkey binary values and read-only replica, retained bytes, effective memory policy, key/admin/password/default/anonymous/IAM denial and actual group/member tag propagation", flush=True)


def cleanup(endpoint, outputs, root):
    wait_available(endpoint, outputs)
    native = connection(outputs, root)
    try:
        native.delete("fixture:retained")
    finally:
        native.close()


def deleted(endpoint, outputs, root):
    try:
        client("elasticache", endpoint).describe_replication_groups(ReplicationGroupId=outputs["name"])
    except ClientError as error:
        require(error.response["Error"]["Code"] == "ReplicationGroupNotFoundFault", str(error))
    else:
        raise RuntimeError("Native cache control resource remains after Terraform destroy")
    retained = json.loads((root / "cache-placement.json").read_text())
    ec2 = client("ec2", endpoint)
    for interface in retained["interfaces"]:
        try:
            ec2.describe_network_interfaces(NetworkInterfaceIds=[interface["NetworkInterfaceId"]])
        except ClientError as error:
            require(error.response["Error"]["Code"] == "InvalidNetworkInterfaceID.NotFound", str(error))
        else:
            raise RuntimeError("Owned native cache ENI remains after destroy")
    host = (root / "docker-host").read_text()
    for kind in ("container", "volume"):
        argv = ["docker", "--host", host, kind, "ls"]
        if kind == "container":
            argv.append("--all")
        listing = command([*argv, "--filter", "label=stackd.valkey.arn="+outputs["arn"], "--quiet"]).stdout
        require(not listing.strip(), f"Exactly owned cache {kind} remains: {listing}")
    listed = command(["docker", "--host", host, "network", "ls", "--quiet"]).stdout.split()
    actual = json.loads(command(["docker", "--host", host, "network", "inspect", *listed]).stdout) if listed else []
    require(not any(network["Name"] in retained["bridges"] for network in actual), "Owned native cache bridge remains")
    for address in (outputs["address"], outputs["reader_address"]):
        try:
            probe = socket.create_connection((address, 6379), timeout=2)
        except (ConnectionRefusedError, TimeoutError):
            pass
        except OSError as error:
            require(error.errno in {errno.EHOSTUNREACH, errno.ENETUNREACH}, str(error))
        else:
            probe.close()
            raise RuntimeError("Deleted native cache still accepts TCP")
    print("Verified signed cache/ENI absence and exact native container/volume/bridge absence", flush=True)


def wait_available(endpoint, outputs):
    deadline = time.monotonic() + 180
    while True:
        group = client("elasticache", endpoint).describe_replication_groups(ReplicationGroupId=outputs["name"])["ReplicationGroups"][0]
        if group["Status"] == "available":
            return group
        require(time.monotonic() < deadline, f"Native cache did not reconcile: {group}")
        time.sleep(0.5)


def ready(endpoint, outputs, root):
    wait_available(endpoint, outputs)


def owned_nodes(outputs, root):
    host = (root / "docker-host").read_text()
    nodes = []
    for role in ("node-1", "node-2"):
        identifiers = command(["docker", "--host", host, "container", "ls", "--all", "--quiet",
                               "--filter", "label=stackd.valkey.arn="+outputs["arn"],
                               "--filter", "label=stackd.valkey.role="+role]).stdout.split()
        require(len(identifiers) == 1, f"Native cache node has ambiguous or missing exact ownership: {role}")
        record = json.loads(command(["docker", "--host", host, "container", "inspect", identifiers[0]]).stdout)[0]
        labels = record["Config"]["Labels"]
        fields = outputs["arn"].split(":")
        require(all(labels.get("stackd.valkey."+key) == value for key, value in
                    {"arn": outputs["arn"], "partition": fields[1], "account": fields[4], "region": fields[3],
                     "role": role, "layout": "managed-v1"}.items()), "Foreign native cache node")
        image = json.loads(command(["docker", "--host", host, "image", "inspect", VALKEY_IMAGE]).stdout)[0]["Id"]
        require(record["Image"] == image and record["Config"]["Image"] == image,
                "Actual cache process does not use the exact pinned image")
        require(not record["HostConfig"]["PortBindings"] and len(record["NetworkSettings"]["Networks"]) == 1,
                "Managed cache exposes an extra published or foreign attachment")
        nodes.append(record)
    require(nodes[0]["Config"]["Labels"]["stackd.valkey.id"] == nodes[1]["Config"]["Labels"]["stackd.valkey.id"],
            "Native cache nodes belong to different incarnations")
    return nodes


def placement_evidence(endpoint, outputs, root):
    nodes = owned_nodes(outputs, root)
    interfaces = client("ec2", endpoint).describe_network_interfaces(
        Filters=[{"Name": "vpc-id", "Values": [outputs["vpc"]]}])["NetworkInterfaces"]
    require(len(interfaces) == 2, "Declared cache topology does not own exactly two actual EC2 reservations")
    by_address = {interface["PrivateIpAddress"]: interface for interface in interfaces}
    for node, address, zone in zip(nodes, (outputs["address"], outputs["reader_address"]),
                                   (outputs["primary_zone"], outputs["reader_zone"])):
        require(address in by_address, "Native endpoint is not an authoritative EC2 reservation")
        interface = by_address[address]
        attachment = next(iter(node["NetworkSettings"]["Networks"].values()))
        require(attachment["IPAddress"] == address and attachment["MacAddress"].lower() == interface["MacAddress"].lower(),
                "Actual native IP/MAC differs from retained EC2 placement")
        subnet = client("ec2", endpoint).describe_subnets(SubnetIds=[interface["SubnetId"]])["Subnets"][0]
        require(interface["SubnetId"] in outputs["subnets"] and subnet["AvailabilityZone"] == zone,
                "Provider cache AZ does not come from its actual selected EC2 subnet")
    evidence = {"interfaces": interfaces, "nodes": nodes,
                "bridges": list({name for node in nodes for name in node["NetworkSettings"]["Networks"]})}
    (root / "cache-placement.json").write_text(json.dumps(evidence, indent=2))


def policy_quarantine(endpoint, outputs, root, dhcp):
    ec2 = client("ec2", endpoint)
    original_nodes = owned_nodes(outputs, root)
    original = ec2.describe_vpcs(VpcIds=[outputs["vpc"]])["Vpcs"][0]["DhcpOptionsId"]
    permission = {"IpProtocol": "tcp", "FromPort": 6379, "ToPort": 6379, "IpRanges": [{"CidrIp": outputs["cidr"]}]}
    options, changed = None, False
    try:
        if dhcp:
            options = ec2.create_dhcp_options(DhcpConfigurations=[
                {"Key": "domain-name-servers", "Values": ["fd00::53"]}])["DhcpOptions"]["DhcpOptionsId"]
            ec2.associate_dhcp_options(DhcpOptionsId=options, VpcId=outputs["vpc"])
        else:
            ec2.revoke_security_group_ingress(GroupId=outputs["group"], IpPermissions=[permission])
        changed = True
        deadline = time.monotonic() + 90
        while True:
            denied_connections = []
            for address in (outputs["address"], outputs["reader_address"]):
                try:
                    probe = socket.create_connection((address, 6379), timeout=1)
                except (ConnectionRefusedError, TimeoutError):
                    denied_connections.append(True)
                except OSError as error:
                    require(error.errno in {errno.EHOSTUNREACH, errno.ENETUNREACH}, str(error))
                    denied_connections.append(True)
                else:
                    probe.close()
                    denied_connections.append(False)
            stopped = all(not node["State"]["Running"] for node in owned_nodes(outputs, root))
            if all(denied_connections) and stopped:
                break
            require(time.monotonic() < deadline, "Cache policy/observation failure left native processes serving beyond90s")
            time.sleep(0.25)
        group = client("elasticache", endpoint).describe_replication_groups(ReplicationGroupId=outputs["name"])["ReplicationGroups"][0]
        require(group["Status"] != "available", "Quarantined cache falsely reports native readiness")
        (root / ("cache-dhcp-denial.json" if dhcp else "cache-sg-denial.json")).write_text(json.dumps({
            "group": group, "native_nodes": owned_nodes(outputs, root), "real_time_bound_seconds": 90}, indent=2, default=str))
    finally:
        if changed:
            if dhcp:
                ec2.associate_dhcp_options(DhcpOptionsId=original, VpcId=outputs["vpc"])
            else:
                ec2.authorize_security_group_ingress(GroupId=outputs["group"], IpPermissions=[permission])
        if options is not None:
            ec2.delete_dhcp_options(DhcpOptionsId=options)
    wait_available(endpoint, outputs)
    require([node["Id"] for node in owned_nodes(outputs, root)] == [node["Id"] for node in original_nodes],
            "Cache quarantine replaced immutable native process identity")
    native = connection(outputs, root)
    try:
        require(native.get("fixture:retained") == (root / "cache-value").read_bytes(),
                "Network quarantine/recovery lost actual native bytes")
    finally:
        native.close()


def role_deletion(endpoint, expected):
    iam = client("iam", endpoint)
    task = iam.delete_service_linked_role(RoleName="AWSServiceRoleForElastiCache")["DeletionTaskId"]
    deadline = time.monotonic() + 30
    while True:
        result = iam.get_service_linked_role_deletion_status(DeletionTaskId=task)
        if result["Status"] in {"SUCCEEDED", "FAILED"}:
            require(result["Status"] == expected, f"Cache SLR deletion did not respect actual usage: {result}")
            return result
        require(time.monotonic() < deadline, "Cache SLR deletion did not complete")
        time.sleep(0.25)


def retire_roles(endpoint, outputs, root):
    with urlopen(endpoint + "/_stackd/clock", timeout=30) as response:
        initial = json.load(response)
    retained = json.loads((root / "cleanup-service-time.json").read_text())
    require(datetime.fromisoformat(initial["time"].replace("Z", "+00:00")) >=
            datetime.fromisoformat(retained["time"].replace("Z", "+00:00")),
            "Cache role retirement moved retained service time backwards")
    request = Request(endpoint + "/_stackd/clock", data=json.dumps({"advance": "1h1s"}).encode(),
                      headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=30) as response:
        advanced = json.load(response)
    result = role_deletion(endpoint, "SUCCEEDED")
    (root / "cache-role-retirement.json").write_text(json.dumps({
        "initial_clock": initial, "advanced_clock": advanced, "deletion": result,
        "expiration_accelerated": "1h1s"}, indent=2))
    print("Verified signed cache SLR deletion after explicit owned session-expiry acceleration", flush=True)
