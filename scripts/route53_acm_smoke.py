#!/usr/bin/env python3
"""Signed Route53/ACM lifecycle, real dig, SQLite reopen, and verified HTTPS.

Uses an already built controller. The exported certificate is decrypted by the
unmodified openssl CLI and loaded by Python's real TLS server. No host DNS or AWS
resources are changed; private material stays in the disposable state directory
and is removed in cleanup, never included in the retained report.
"""
import argparse
from datetime import datetime, timedelta, timezone
import http.server
import json
import re
import ssl
import subprocess
import threading
import urllib.request
import uuid
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from ssm_managed_guest_smoke import Smoke as BaseSmoke, REGION


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"dns-validated-acm-tls")

    def log_message(self, *_):
        pass


class Smoke(BaseSmoke):
    def __init__(self, args):
        self.args = args
        self.state = args.state_directory.resolve()
        self.state.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.account = "815602947204"
        self.prefix = "stackd-next-dns-" + uuid.uuid4().hex[:10]
        self.zone_name = self.prefix + ".example.test"
        self.hostname = "www." + self.zone_name
        self.endpoint = f"http://127.0.0.1:{args.port}"
        self.dns_endpoint = f"127.0.0.1:{args.dns_port}"
        self.epoch = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        self.process = self.log = self.tls_server = None
        self.clients, self.owned = {}, {}
        self.data = {"source": "actual CLI + signed SDK + unmodified dig UDP/TCP + openssl + verified HTTPS",
                     "account": self.account, "calls": [], "observations": {}, "owned": self.owned, "cleanup": {}}
        self.save()

    def client(self, service, creds=None, region=REGION):
        if creds is None and (service, region) in self.clients:
            return self.clients[(service, region)]
        creds = creds or {"AccessKeyId": "test", "SecretAccessKey": "test"}
        result = boto3.client(service, region_name=region, endpoint_url=self.endpoint,
            aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds.get("SessionToken"),
            config=Config(retries={"max_attempts": 0}, connect_timeout=5, read_timeout=30))
        if creds["AccessKeyId"] == "test":
            self.clients[(service, region)] = result
        return result

    def start(self):
        self.log = (self.state / "controller.log").open("ab")
        self.process = subprocess.Popen([str(self.args.binary.resolve()), "-listen", f"0.0.0.0:{self.args.port}",
            "-database", str(self.state / "state.sqlite"), "-account-id", self.account,
            "-clock-start", self.epoch, "-dns-listen", self.dns_endpoint,
            "-docker-host", "unix:///var/run/docker.sock",
            "-elbv2-node-executable", str(self.args.elbv2_node_executable.resolve())], stdout=self.log, stderr=subprocess.STDOUT)
        def ready():
            if self.process.poll() is not None:
                raise RuntimeError((self.state / "controller.log").read_text())
            try:
                return self.client("sts").get_caller_identity()["Account"] == self.account
            except Exception:
                return False
        self.wait("controller ready", ready, bool, 60)

    def advance(self, seconds=61):
        request = urllib.request.Request(self.endpoint + "/_stackd/clock", data=json.dumps({"advance": f"{seconds}s"}).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=30) as response:
            json.load(response)
        with urllib.request.urlopen(urllib.request.Request(self.endpoint + "/_stackd/jobs/drain?limit=256", data=b""), timeout=30) as response:
            json.load(response)

    def dns(self, name, typ="A", tcp=False):
        command = ["dig", "@127.0.0.1", "-p", str(self.args.dns_port), name, typ, "+noall", "+answer", "+comments", "+time=2", "+tries=1"]
        if tcp:
            command.append("+tcp")
        text = subprocess.run(command, text=True, capture_output=True, check=True).stdout
        status = re.search(r"status: ([A-Z]+)", text)
        assert status, text
        records = []
        for line in text.splitlines():
            if not line or line.startswith(";"):
                continue
            fields = line.split(None, 4)
            records.append({"name": fields[0], "ttl": int(fields[1]), "type": fields[3], "value": fields[4]})
        return {"status": status.group(1), "records": records}

    def change(self, records, action="UPSERT"):
        return self.call("records-" + action, "route53", "change_resource_record_sets", HostedZoneId=self.owned["zone"],
            ChangeBatch={"Changes": [{"Action": action, "ResourceRecordSet": record} for record in records]})

    def description(self):
        return self.client("acm").describe_certificate(CertificateArn=self.owned["certificate"])["Certificate"]

    def status(self, expected):
        self.advance()
        value = self.description()
        assert value["Status"] == expected, value
        return value

    def run(self):
        self.start()
        zone = self.call("create-zone", "route53", "create_hosted_zone", Name=self.zone_name, CallerReference=self.prefix)
        self.owned["zone"] = zone["HostedZone"]["Id"]
        record = {"Name": self.hostname, "Type": "A", "TTL": 30, "ResourceRecords": [{"Value": "127.0.0.1"}]}
        change = self.change([record])
        self.advance()
        assert self.client("route53").get_change(Id=change["ChangeInfo"]["Id"])["ChangeInfo"]["Status"] == "INSYNC"
        for tcp in (False, True):
            answer = self.dns(self.hostname, tcp=tcp)
            assert answer["status"] == "NOERROR" and [row["value"] for row in answer["records"]] == ["127.0.0.1"], answer
        assert self.dns(self.hostname, "AAAA") == {"status": "NOERROR", "records": []}
        invalid = {"Name": "outside.invalid", "Type": "A", "TTL": 30, "ResourceRecords": [{"Value": "127.0.0.2"}]}
        self.expect("atomic-out-of-zone", "InvalidChangeBatch", "route53", "change_resource_record_sets", HostedZoneId=self.owned["zone"],
            ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": record}, {"Action": "CREATE", "ResourceRecordSet": invalid}]})
        assert self.dns(self.hostname)["records"][0]["value"] == "127.0.0.1"
        wrong_delete = dict(record, TTL=31)
        self.expect("nonmatching-delete", "InvalidChangeBatch", "route53", "change_resource_record_sets", HostedZoneId=self.owned["zone"],
            ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": wrong_delete}]})
        requested = self.call("request-certificate", "acm", "request_certificate", DomainName=self.hostname,
            SubjectAlternativeNames=["other." + self.zone_name], ValidationMethod="DNS", Options={"Export": "ENABLED"})
        self.owned["certificate"] = requested["CertificateArn"]
        pending = self.status("PENDING_VALIDATION")
        options = pending["DomainValidationOptions"]
        assert len(options) == 2 and all(row["ValidationStatus"] == "PENDING_VALIDATION" for row in options), options
        validation = [{"Name": row["ResourceRecord"]["Name"], "Type": "CNAME", "TTL": 30, "ResourceRecords": [{"Value": row["ResourceRecord"]["Value"]}]} for row in options]
        wrong = dict(validation[0], ResourceRecords=[{"Value": "_not-the-proof.acm-validations.aws."}])
        self.change([wrong, validation[1]])
        self.status("PENDING_VALIDATION")
        self.change([validation[0]])
        issued = self.status("ISSUED")
        for item in validation:
            answer = self.dns(item["Name"], "CNAME")
            assert [row["value"] for row in answer["records"]] == [item["ResourceRecords"][0]["Value"]], answer
        self.data["observations"]["validation"] = {"missing": "PENDING_VALIDATION", "nonmatching": "PENDING_VALIDATION", "matching": issued["Status"], "domains": [row["DomainName"] for row in options]}
        self.expect("cross-region-certificate", "ResourceNotFoundException", "acm", "describe_certificate",
            client=self.client("acm", region="eu-west-1"), CertificateArn=self.owned["certificate"])
        self.call("create-restricted-user", "iam", "create_user", UserName=self.prefix)
        self.owned["user"] = self.prefix
        credentials = self.client("iam").create_access_key(UserName=self.prefix)["AccessKey"]
        self.owned["access_key_id"] = credentials["AccessKeyId"]
        self.expect("iam-dns-deny", "AccessDenied", "route53", "list_resource_record_sets", client=self.client("route53", credentials), HostedZoneId=self.owned["zone"])
        self.expect("iam-acm-deny", "AccessDeniedException", "acm", "describe_certificate", client=self.client("acm", credentials), CertificateArn=self.owned["certificate"])
        material = self.client("acm").get_certificate(CertificateArn=self.owned["certificate"])
        self.tls(material)
        self.alb(material)
        self.stop()
        self.start()
        retained = self.description()
        assert retained["Status"] == "ISSUED" and retained["Serial"] == issued["Serial"], retained
        assert self.client("acm").get_certificate(CertificateArn=self.owned["certificate"])["Certificate"] == material["Certificate"]
        self.wait("reopened native ALB HTTPS", lambda: self.alb_request(material), bool, 180)
        self.renewal(validation, issued, material)
        self.change([self.owned["alias"]], "DELETE")
        empty = self.dns(self.hostname)
        assert empty == {"status": "NOERROR", "records": []}, empty
        self.change(validation, "DELETE")
        absent = self.dns(self.hostname)
        assert absent == {"status": "NXDOMAIN", "records": []}, absent
        self.data["observations"]["restart"] = {"same_certificate_serial": True, "retained_dns": True,
            "removed_alias_with_validation_descendant": empty, "removed_dns": absent}
        self.save()

    def alb(self, material):
        octet = 16 + uuid.uuid4().int % 220
        network = f"10.198.{octet}"
        self.owned["vpc"] = self.call("create-vpc", "ec2", "create_vpc", CidrBlock=network + ".0/24")["Vpc"]["VpcId"]
        self.owned["subnets"] = []
        for index in range(2):
            subnet = self.call("create-subnet", "ec2", "create_subnet", VpcId=self.owned["vpc"],
                CidrBlock=network + f".{index * 64}/26", AvailabilityZone=REGION + chr(ord("a") + index))["Subnet"]["SubnetId"]
            self.owned["subnets"].append(subnet)
        self.owned["security_group"] = self.call("create-security-group", "ec2", "create_security_group",
            VpcId=self.owned["vpc"], GroupName=self.prefix, Description=self.prefix)["GroupId"]
        self.call("allow-native-https", "ec2", "authorize_security_group_ingress", GroupId=self.owned["security_group"],
            IpPermissions=[{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
        lb = self.call("create-alb", "elbv2", "create_load_balancer", Name=self.prefix[:32], Type="application", Scheme="internal",
            Subnets=self.owned["subnets"], SecurityGroups=[self.owned["security_group"]])["LoadBalancers"][0]
        self.owned["load_balancer"] = lb["LoadBalancerArn"]
        self.call("create-https-listener", "elbv2", "create_listener", LoadBalancerArn=lb["LoadBalancerArn"], Protocol="HTTPS", Port=443,
            Certificates=[{"CertificateArn": self.owned["certificate"]}], SslPolicy="ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
            DefaultActions=[{"Type": "fixed-response", "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain", "MessageBody": "native-alb-acm-tls"}}])
        alias = {"Name": self.hostname, "Type": "A", "AliasTarget": {"HostedZoneId": lb["CanonicalHostedZoneId"], "DNSName": lb["DNSName"], "EvaluateTargetHealth": False}}
        invalid = dict(alias, AliasTarget=dict(alias["AliasTarget"], HostedZoneId="ZWRONGALBZONE"))
        self.expect("wrong-alias-zone", "InvalidChangeBatch", "route53", "change_resource_record_sets", HostedZoneId=self.owned["zone"],
            ChangeBatch={"Changes": [{"Action": "UPSERT", "ResourceRecordSet": invalid}]})
        self.change([alias])
        self.owned["alias"] = alias
        self.expect("in-use-certificate", "ResourceInUseException", "acm", "delete_certificate", CertificateArn=self.owned["certificate"])
        assert lb["LoadBalancerArn"] in self.description()["InUseBy"]
        self.wait("native ALB HTTPS", lambda: self.alb_request(material), bool, 180)
        shadow = self.call("create-shadow-zone", "route53", "create_hosted_zone", Name=lb["DNSName"], CallerReference=self.prefix + "-shadow")
        self.owned["shadow_zone"] = shadow["HostedZone"]["Id"]
        shadow_record = {"Name": lb["DNSName"], "Type": "A", "TTL": 30, "ResourceRecords": [{"Value": "127.0.0.99"}]}
        self.call("shadow-managed-owner", "route53", "change_resource_record_sets", HostedZoneId=self.owned["shadow_zone"],
            ChangeBatch={"Changes": [{"Action": "CREATE", "ResourceRecordSet": shadow_record}]})
        addresses = [row["value"] for row in self.dns(lb["DNSName"])["records"]]
        assert addresses and "127.0.0.99" not in addresses, addresses
        self.data["observations"]["managed_dns_precedence"] = {"shadow_record_not_served": True, "current_owner_addresses": addresses}
        self.data["observations"]["alb"] = {"alias": alias, "verified_certificate": True, "in_use_delete": "ResourceInUseException"}
        self.save()

    def alb_request(self, material):
        self.advance(1)
        records = self.dns(self.hostname)["records"]
        if not records:
            return False
        (self.state / "chain.pem").write_text(material["CertificateChain"])
        with urllib.request.urlopen(self.endpoint + "/_stackd/clock", timeout=5) as response:
            now = datetime.fromisoformat(json.load(response)["time"].replace("Z", "+00:00"))
        command = ["openssl", "s_client", "-connect", records[0]["value"] + ":443", "-servername", self.hostname,
            "-CAfile", str(self.state / "chain.pem"), "-verify_hostname", self.hostname, "-verify_return_error",
            "-attime", str(int(now.timestamp())), "-showcerts", "-ign_eof", "-ignore_unexpected_eof"]
        try:
            result = subprocess.run(command, input="GET / HTTP/1.0\r\nHost: " + self.hostname + "\r\n\r\n", text=True,
                capture_output=True, timeout=10)
        except subprocess.TimeoutExpired:
            self.data["observations"]["last_alb_probe"] = {"error": "OpenSSL client exceeded 10-second deadline"}
            self.save()
            return False
        if result.returncode or "native-alb-acm-tls" not in result.stdout:
            self.data["observations"]["last_alb_probe"] = {"exit_code": result.returncode, "stderr": result.stderr, "http_body_observed": "native-alb-acm-tls" in result.stdout}
            self.save()
            return False
        leaf = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", result.stdout, re.S)
        assert leaf and ssl.PEM_cert_to_DER_cert(leaf.group()) == ssl.PEM_cert_to_DER_cert(material["Certificate"]), result.stdout
        self.data["observations"]["last_alb_probe"] = {"exit_code": result.returncode, "verified_current_certificate": True, "http_body_observed": True}
        return True

    def renewal(self, validation, issued, material):
        self.change([validation[0]], "DELETE")
        with urllib.request.urlopen(self.endpoint + "/_stackd/clock", timeout=5) as response:
            now = datetime.fromisoformat(json.load(response)["time"].replace("Z", "+00:00"))
        due = issued["NotAfter"] - timedelta(days=45) + timedelta(seconds=1)
        self.advance(int((due - now).total_seconds()))
        pending = self.description()
        assert pending["Status"] == "ISSUED" and pending["Serial"] == issued["Serial"], pending
        assert pending["RenewalSummary"]["RenewalStatus"] == "PENDING_VALIDATION", pending
        assert self.alb_request(material), "old valid leaf unavailable during renewal validation"
        self.change([validation[0]])
        self.advance()
        renewed = self.description()
        assert renewed["Status"] == "ISSUED" and renewed["Serial"] != issued["Serial"], renewed
        assert renewed["RenewalSummary"]["RenewalStatus"] == "SUCCESS", renewed
        refreshed = self.client("acm").get_certificate(CertificateArn=self.owned["certificate"])
        assert self.alb_request(refreshed), "renewed leaf did not reach the existing native listener"
        self.data["observations"]["renewal"] = {"pending_with_missing_cname": True, "old_leaf_remained_usable": True,
            "new_leaf_on_existing_listener": True, "native_openssl_service_time_verified": True}

    def tls(self, material):
        password = uuid.uuid4().hex
        exported = self.client("acm").export_certificate(CertificateArn=self.owned["certificate"], Passphrase=password.encode())
        for name, value in (("leaf.pem", exported["Certificate"]), ("chain.pem", material["CertificateChain"]), ("encrypted-key.pem", exported["PrivateKey"])):
            path = self.state / name
            path.write_text(value)
            path.chmod(0o600)
        subprocess.run(["openssl", "pkey", "-in", str(self.state / "encrypted-key.pem"), "-passin", "stdin", "-out", str(self.state / "key.pem")],
            input=password + "\n", text=True, check=True, capture_output=True)
        (self.state / "key.pem").chmod(0o600)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(self.state / "leaf.pem", self.state / "key.pem")
        self.tls_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.tls_server.socket = server_context.wrap_socket(self.tls_server.socket, server_side=True)
        worker = threading.Thread(target=self.tls_server.serve_forever, daemon=True)
        worker.start()
        context = ssl.create_default_context(cafile=str(self.state / "chain.pem"))
        import socket
        address = self.dns(self.hostname)["records"][0]["value"]
        with socket.create_connection((address, self.tls_server.server_port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=self.hostname) as connection:
                protocol = connection.version()
                connection.sendall(("GET / HTTP/1.0\r\nHost: " + self.hostname + "\r\n\r\n").encode())
                response = b""
                while part := connection.recv(4096):
                    response += part
                assert response.startswith(b"HTTP/1.0 200") and response.endswith(b"dns-validated-acm-tls"), response
                self.data["observations"]["tls"] = {"protocol": protocol, "hostname_verified": self.hostname, "trust": "GetCertificate local CA chain", "http_body": "dns-validated-acm-tls", "openssl_decrypted_export": True}
        self.tls_server.shutdown()
        self.tls_server.server_close()
        worker.join()
        self.tls_server = None

    def cleanup(self):
        if self.tls_server:
            self.tls_server.shutdown()
            self.tls_server.server_close()
        if self.owned and (self.process is None or self.process.poll() is not None):
            self.start()
        if self.owned.get("shadow_zone"):
            records = self.client("route53").list_resource_record_sets(HostedZoneId=self.owned["shadow_zone"])["ResourceRecordSets"]
            changes = [{"Action": "DELETE", "ResourceRecordSet": row} for row in records if row["Type"] not in ("NS", "SOA")]
            if changes:
                self.call("cleanup-shadow-records", "route53", "change_resource_record_sets", HostedZoneId=self.owned["shadow_zone"], ChangeBatch={"Changes": changes})
            self.call("cleanup-shadow-zone", "route53", "delete_hosted_zone", Id=self.owned["shadow_zone"])
        if self.owned.get("load_balancer"):
            self.call("cleanup-alb", "elbv2", "delete_load_balancer", LoadBalancerArn=self.owned["load_balancer"])
            def removed():
                self.advance(1)
                return not self.client("ec2").describe_network_interfaces(Filters=[{"Name": "vpc-id", "Values": [self.owned["vpc"]]}])["NetworkInterfaces"]
            self.wait("native ALB removal", removed, bool, 180)
        if self.owned.get("security_group"):
            self.call("cleanup-security-group", "ec2", "delete_security_group", GroupId=self.owned["security_group"])
        for subnet in self.owned.get("subnets", []):
            self.call("cleanup-subnet", "ec2", "delete_subnet", SubnetId=subnet)
        if self.owned.get("vpc"):
            self.call("cleanup-vpc", "ec2", "delete_vpc", VpcId=self.owned["vpc"])
        if self.owned.get("certificate"):
            self.call("cleanup-certificate", "acm", "delete_certificate", CertificateArn=self.owned["certificate"])
        if self.owned.get("user"):
            if self.owned.get("access_key_id"):
                self.client("iam").delete_access_key(UserName=self.owned["user"], AccessKeyId=self.owned["access_key_id"])
            self.call("cleanup-user", "iam", "delete_user", UserName=self.owned["user"])
        if self.owned.get("zone"):
            records = self.client("route53").list_resource_record_sets(HostedZoneId=self.owned["zone"])["ResourceRecordSets"]
            records = [row for row in records if not (row["Name"].rstrip(".") == self.zone_name and row["Type"] in ("SOA", "NS"))]
            if records:
                self.change(records, "DELETE")
            self.call("cleanup-zone", "route53", "delete_hosted_zone", Id=self.owned["zone"])
            assert self.dns(self.hostname)["status"] == "REFUSED"
        for name in ("leaf.pem", "chain.pem", "encrypted-key.pem", "key.pem"):
            (self.state / name).unlink(missing_ok=True)
        self.data["cleanup"].update(owned_resources_removed=True, exported_material_removed=True, no_host_dns_changes=True)
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--elbv2-node-executable", type=Path, required=True)
    parser.add_argument("--state-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18674)
    parser.add_argument("--dns-port", type=int, default=18675)
    args = parser.parse_args()
    smoke = Smoke(args)
    try:
        smoke.run()
    finally:
        try:
            smoke.cleanup()
        finally:
            smoke.stop()
    print(json.dumps(smoke.data["observations"], indent=2))


if __name__ == "__main__":
    main()
