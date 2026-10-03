#!/usr/bin/env python3
"""Local signed-SDK RAM sharing with real firmware QEMU networking and recovery.

Reuses the existing launch-template/SSM smoke controller and sparse image importer.
No native AWS calls, SSH, fake guest, resource proxy or replacement executor.
Subnet shares use actual Organizations auto-acceptance, not external invitations.
"""
import argparse
import base64
import ipaddress
import json
from pathlib import Path
import urllib.error
import urllib.request
import uuid

from botocore.exceptions import ClientError
from ec2_launch_template_smoke import Smoke as FirmwareSmoke
from ssm_managed_guest_smoke import REGION


class Smoke(FirmwareSmoke):
    def __init__(self, args):
        if args.provider_account == args.participant_account:
            raise ValueError("Provider and participant must be distinct local accounts")
        if args.output.exists():
            raise ValueError("Refusing to overwrite existing evidence")
        super().__init__(args)
        self.account = args.provider_account
        self.participant_account = args.participant_account
        self.prefix = self.prefix.replace("stackd-lt-guest", "stackd-ram-subnet")
        self.account_clients = {}
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.private_ip = str(ipaddress.ip_network(args.cidr).network_address + 10)
        self.data.update(source="local actual retained CLI, signed cross-account SDKs and firmware QEMU packets; not native AWS evidence",
                         account=self.account, participant_account=self.participant_account, prefix=self.prefix,
                         cidr=args.cidr, packet_port=args.packet_port)
        self.save()

    def scoped_client(self, service, account):
        key = (service, account)
        if key not in self.account_clients:
            self.account_clients[key] = super().client(service, {"AccessKeyId": account, "SecretAccessKey": "test"})
        return self.account_clients[key]

    def client(self, service, creds=None):
        if creds is not None:
            return super().client(service, creds)
        account = self.participant_account if service in {"ec2", "ebs"} else self.account
        return self.scoped_client(service, account)

    def provider(self, service):
        return self.scoped_client(service, self.account)

    def participant(self, service):
        return self.scoped_client(service, self.participant_account)

    def guest_script(self):
        program = '''import http.server,json,pathlib,sys,urllib.parse
marker,instance,port=sys.argv[1:]
boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
class Receiver(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        nonce=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)['nonce'][0]
        body=json.dumps({'marker':marker,'instance_id':instance,'boot_id':boot,'nonce':nonce}).encode()
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers()
        self.wfile.write(body)
http.server.ThreadingHTTPServer(('0.0.0.0',int(port)),Receiver).serve_forever()
'''
        encoded = base64.b64encode(program.encode()).decode()
        return f'''#!/bin/bash
set -eu
exec > >(tee /dev/console) 2>&1
token=$(curl -fsS -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 300' http://169.254.169.254/latest/api/token)
instance=$(curl -fsS -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/instance-id)
printf '%s' '{encoded}' | base64 -d >/var/tmp/ram-packet-receiver.py
printf 'STACKD_RAM_FIRMWARE_BOOT_OK %s\\n' "$instance"
exec python3 /var/tmp/ram-packet-receiver.py '{self.prefix}' "$instance" {self.args.packet_port}
'''

    def packet(self):
        nonce = uuid.uuid4().hex
        try:
            with self.http.open(f"http://{self.private_ip}:{self.args.packet_port}/proof?nonce={nonce}", timeout=3) as response:
                result = json.load(response)
        except urllib.error.HTTPError:
            raise
        except (urllib.error.URLError, TimeoutError, OSError):
            return None
        assert result["nonce"] == nonce and result["marker"] == self.prefix
        assert result["instance_id"] == self.owned["instance"]
        uuid.UUID(result["boot_id"])
        return result

    def observe_packet(self, label, boot_id=None, seconds=90):
        result = self.wait(label, self.packet, bool, seconds, 1)
        if boot_id is not None:
            assert result["boot_id"] == boot_id, "Retained controller restart rebooted/replaced the guest"
        self.data["observations"][label] = result
        self.save()
        return result

    def run(self):
        self.prepare()
        o = self.owned
        owner_ec2, participant_ram = self.provider("ec2"), self.participant("ram")
        o["identity_user"] = self.prefix + "-participant"
        user = self.call("register-local-participant-identity", "iam", "create_user", client=self.participant("iam"), UserName=o["identity_user"])["User"]
        assert user["Arn"].split(":")[4] == self.participant_account
        org = self.call("create-isolated-local-organization", "organizations", "create_organization", FeatureSet="ALL")["Organization"]
        o["organization"] = org["Id"]
        invitation = self.call("invite-local-participant", "organizations", "invite_account_to_organization", Target={"Type":"ACCOUNT", "Id":self.participant_account})["Handshake"]
        accepted = self.call("participant-accepts-organization", "organizations", "accept_handshake", client=self.participant("organizations"), HandshakeId=invitation["Id"])["Handshake"]
        assert accepted["State"] == "ACCEPTED"
        o["joined"] = True
        enabled = self.call("enable-local-RAM-organization-authority", "ram", "enable_sharing_with_aws_organization")
        assert enabled["returnValue"] is True
        o["ram_enabled"] = True
        o["vpc"] = self.call("provider-vpc", "ec2", "create_vpc", client=owner_ec2, CidrBlock=self.args.cidr)["Vpc"]["VpcId"]
        o["subnet"] = self.call("provider-subnet", "ec2", "create_subnet", client=owner_ec2, VpcId=o["vpc"], CidrBlock=self.args.cidr, AvailabilityZone=REGION+"a")["Subnet"]["SubnetId"]
        subnet_arn = f"arn:aws:ec2:{REGION}:{self.account}:subnet/{o['subnet']}"
        o["share"] = self.call("share-owner-subnet", "ram", "create_resource_share", name=self.prefix, resourceArns=[subnet_arn], principals=[self.participant_account], allowExternalPrincipals=False)["resourceShare"]["resourceShareArn"]
        for association in ("RESOURCE", "PRINCIPAL"):
            out = self.call("associated-"+association.lower(), "ram", "get_resource_share_associations", associationType=association, resourceShareArns=[o["share"]])
            rows = out["resourceShareAssociations"]
            assert len(rows) == 1 and rows[0]["status"] == "ASSOCIATED", rows
        invitations = self.call("organization-share-needs-no-invitation", "ram", "get_resource_share_invitations", client=participant_ram, resourceShareArns=[o["share"]])
        assert invitations["resourceShareInvitations"] == []
        discovered = self.call("participant-resolves-current-owner-subnet", "ec2", "describe_subnets", SubnetIds=[o["subnet"]])["Subnets"]
        assert len(discovered) == 1 and discovered[0]["OwnerId"] == self.account
        self.expect("participant-cannot-delete-owner-subnet", "InvalidSubnetID.NotFound", "ec2", "delete_subnet", SubnetId=o["subnet"])
        o["sg"] = self.call("participant-owned-security-group", "ec2", "create_security_group", VpcId=o["vpc"], GroupName=self.prefix, Description="Owned RAM guest packet receiver")["GroupId"]
        ingress = [{"IpProtocol":"tcp", "FromPort":self.args.packet_port, "ToPort":self.args.packet_port, "IpRanges":[{"CidrIp":self.args.cidr}]}]
        self.call("participant-authorizes-real-packets", "ec2", "authorize_security_group_ingress", GroupId=o["sg"], IpPermissions=ingress)
        o["eni"] = self.call("participant-owned-ENI-in-owner-subnet", "ec2", "create_network_interface", SubnetId=o["subnet"], PrivateIpAddress=self.private_ip, Groups=[o["sg"]])["NetworkInterface"]["NetworkInterfaceId"]
        interface = self.call("owner-observes-participant-ENI", "ec2", "describe_network_interfaces", client=owner_ec2, NetworkInterfaceIds=[o["eni"]])["NetworkInterfaces"][0]
        assert interface["OwnerId"] == self.participant_account and interface["SubnetId"] == o["subnet"]
        self.import_image()  # Actual EBS blocks and AMI are participant-owned.
        launched = self.call("participant-real-firmware-launch", "ec2", "run_instances", ImageId=o["image"], InstanceType="t3.nano", MinCount=1, MaxCount=1, ClientToken=self.prefix,
                             NetworkInterfaces=[{"NetworkInterfaceId":o["eni"], "DeviceIndex":0, "DeleteOnTermination":False}],
                             MetadataOptions={"HttpTokens":"required"}, UserData=self.guest_script())
        o["instance"] = launched["Instances"][0]["InstanceId"]
        self.save()
        running = self.wait("real shared-subnet guest running", lambda:self.client("ec2").describe_instances(InstanceIds=[o["instance"]]), lambda r:r["Reservations"][0]["Instances"][0]["State"]["Name"] == "running", 240)
        reservation = running["Reservations"][0]
        assert reservation["OwnerId"] == self.participant_account
        instance = reservation["Instances"][0]
        assert instance["SubnetId"] == o["subnet"] and instance["PrivateIpAddress"] == self.private_ip
        self.data["observations"]["running_guest"] = instance
        console = self.wait("firmware user data", lambda:self.client("ec2").get_console_output(InstanceId=o["instance"], Latest=True), lambda r:"STACKD_RAM_FIRMWARE_BOOT_OK" in r.get("Output", ""), 300, 2)
        self.data["observations"]["firmware_console"] = console["Output"]
        first = self.observe_packet("real_packets_before_restart")
        self.stop()
        self.start()
        self.observe_packet("real_packets_after_restart", first["boot_id"])
        self.call("revoke-participant-current-share", "ram", "disassociate_resource_share", resourceShareArn=o["share"], principals=[self.participant_account])
        self.expect("revoked-new-ENI-denied", "InvalidSubnetID.NotFound", "ec2", "create_network_interface", SubnetId=o["subnet"], Groups=[o["sg"]])
        self.expect("revoked-new-guest-placement-denied", "InvalidSubnetID.NotFound", "ec2", "run_instances", ImageId=o["image"], InstanceType="t3.nano", MinCount=1, MaxCount=1, SubnetId=o["subnet"], SecurityGroupIds=[o["sg"]], ClientToken=self.prefix+"-revoked")
        retained = self.call("revocation-retains-participant-ENI", "ec2", "describe_network_interfaces", NetworkInterfaceIds=[o["eni"]])["NetworkInterfaces"][0]
        assert retained["PrivateIpAddress"] == self.private_ip and retained["Attachment"]["InstanceId"] == o["instance"]
        self.observe_packet("real_packets_after_RAM_revocation", first["boot_id"])
        self.call("retained-participant-SG-denies-packets", "ec2", "revoke_security_group_ingress", GroupId=o["sg"], IpPermissions=ingress)
        self.wait("actual SG packet denial", lambda:self.packet() is None, bool, 30)
        self.data["observations"]["retained_SG_packet_denial"] = True
        self.call("retained-participant-SG-restores-packets", "ec2", "authorize_security_group_ingress", GroupId=o["sg"], IpPermissions=ingress)
        self.observe_packet("real_packets_after_SG_restore", first["boot_id"])
        self.stop()
        self.start()
        self.observe_packet("real_packets_after_revoked_restart", first["boot_id"])
        self.expect("revocation-retained-after-restart", "InvalidSubnetID.NotFound", "ec2", "create_network_interface", SubnetId=o["subnet"], Groups=[o["sg"]])
        self.data["observations"]["organization_auto_acceptance"] = True
        self.data["complete"] = True
        self.save()

    def cleanup(self):
        if self.process is None:
            self.start()
        failures = []
        def attempt(label, service, operation, client=None, missing=(), **kwargs):
            try:
                return self.call(label, service, operation, client=client, **kwargs)
            except ClientError as error:
                if error.response["Error"]["Code"] not in missing:
                    failures.append({"label":label, "error":str(error)})
            except Exception as error:
                failures.append({"label":label, "error":str(error)})
        o = self.owned
        # Include any unexpected successful allocation in a negative call: do not
        # leak a second guest/ENI just because its expected rejection failed.
        instances, interfaces = set(), set()
        for row in self.data["calls"]:
            if row.get("code") != "Success": continue
            if row["operation"] == "run_instances":
                instances.update(x["InstanceId"] for x in row["output"]["Instances"])
            if row["operation"] == "create_network_interface":
                interfaces.add(row["output"]["NetworkInterface"]["NetworkInterfaceId"])
        for instance in instances:
            description = attempt("cleanup-instance-volumes", "ec2", "describe_instances", InstanceIds=[instance])
            volumes = [] if description is None else [x["Ebs"]["VolumeId"] for x in description["Reservations"][0]["Instances"][0].get("BlockDeviceMappings", [])]
            attempt("cleanup-terminate-owned-guest", "ec2", "terminate_instances", InstanceIds=[instance])
            try:
                self.wait("exact owned guest termination", lambda:self.client("ec2").describe_instances(InstanceIds=[instance]), lambda r:r["Reservations"][0]["Instances"][0]["State"]["Name"] == "terminated", 180)
                for volume in volumes:
                    self.expect("cleanup-root-volume-absence", "InvalidVolume.NotFound", "ec2", "describe_volumes", VolumeIds=[volume])
            except Exception as error:
                failures.append({"label":"guest-termination", "error":str(error)})
        for interface in interfaces:
            attempt("cleanup-participant-ENI", "ec2", "delete_network_interface", NetworkInterfaceId=interface, missing=("InvalidNetworkInterfaceID.NotFound",))
        if "sg" in o: attempt("cleanup-participant-SG", "ec2", "delete_security_group", GroupId=o["sg"], missing=("InvalidGroup.NotFound",))
        if "image" in o: attempt("cleanup-participant-image", "ec2", "deregister_image", ImageId=o["image"], missing=("InvalidAMIID.NotFound",))
        if "snapshot" in o: attempt("cleanup-participant-snapshot", "ec2", "delete_snapshot", SnapshotId=o["snapshot"], missing=("InvalidSnapshot.NotFound",))
        if "share" in o: attempt("cleanup-RAM-share", "ram", "delete_resource_share", resourceShareArn=o["share"])
        if "subnet" in o: attempt("cleanup-owner-subnet", "ec2", "delete_subnet", client=self.provider("ec2"), SubnetId=o["subnet"], missing=("InvalidSubnetID.NotFound",))
        if "vpc" in o: attempt("cleanup-owner-VPC", "ec2", "delete_vpc", client=self.provider("ec2"), VpcId=o["vpc"], missing=("InvalidVpcID.NotFound",))
        if o.get("ram_enabled"): attempt("cleanup-RAM-trusted-access", "organizations", "disable_aws_service_access", ServicePrincipal="ram.amazonaws.com")
        if o.get("joined"): attempt("cleanup-participant-membership", "organizations", "remove_account_from_organization", AccountId=self.participant_account)
        if "organization" in o: attempt("cleanup-owned-organization", "organizations", "delete_organization")
        if "identity_user" in o: attempt("cleanup-participant-identity", "iam", "delete_user", client=self.participant("iam"), UserName=o["identity_user"], missing=("NoSuchEntity",))
        for account, role in [(self.account,"AWSServiceRoleForResourceAccessManager"), (self.account,"AWSServiceRoleForOrganizations"), (self.participant_account,"AWSServiceRoleForOrganizations")]:
            iam = self.scoped_client("iam", account)
            deletion = attempt("cleanup-owned-service-role", "iam", "delete_service_linked_role", client=iam, RoleName=role, missing=("NoSuchEntity",))
            if deletion is not None:
                try:
                    status = self.wait("owned service-role deletion", lambda:iam.get_service_linked_role_deletion_status(DeletionTaskId=deletion["DeletionTaskId"]), lambda r:r["Status"] in {"SUCCEEDED","FAILED"}, 120)
                    assert status["Status"] == "SUCCEEDED", status
                except Exception as error:
                    failures.append({"label":"service-role-deletion", "error":str(error)})
        self.data["cleanup"] = {"complete":not failures, "terminated_instances":sorted(instances), "deleted_interfaces":sorted(interfaces), "failures":failures}
        self.save()
        if failures: raise RuntimeError("Exact owned cleanup failed; retained evidence identifies remaining resources")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--raw-image", type=Path, required=True)
    parser.add_argument("--bios", type=Path, required=True)
    parser.add_argument("--state-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--provider-account", default="815602947211")
    parser.add_argument("--participant-account", default="815602947212")
    parser.add_argument("--cidr", default="10.194.28.0/24")
    parser.add_argument("--gateway", default="10.194.28.1")
    parser.add_argument("--port", type=int, default=15981)
    parser.add_argument("--packet-port", type=int, default=18081)
    args = parser.parse_args()
    args.binary = args.binary.resolve()
    smoke = Smoke(args)
    try:
        smoke.run()
    except BaseException as error:
        smoke.data["failure"] = {"type":type(error).__name__, "message":str(error)}
        smoke.save()
        raise
    finally:
        try:
            smoke.cleanup()
        finally:
            smoke.stop()
    print(json.dumps({"complete":smoke.data.get("complete",False), "cleanup":smoke.data["cleanup"], "output":str(args.output)}))
