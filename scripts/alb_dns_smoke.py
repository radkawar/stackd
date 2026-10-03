#!/usr/bin/env python3
"""Actual DNS UDP/TCP -> hostname HTTP/TLS, retained restart, subnet/deletion smoke.

Inputs are prebuilt controller/native relay binaries. Uses owned local resources
only; does not modify system DNS, public DNS, or AWS standing infrastructure.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import ssl
import subprocess
import uuid

import boto3
from botocore.config import Config

from dns_http_client import opener, query
from ssm_managed_guest_smoke import Smoke as BaseSmoke, REGION


class Smoke(BaseSmoke):
    def __init__(self, args):
        self.args = args
        self.state = args.state_directory.resolve()
        self.state.mkdir(parents=True, exist_ok=False)
        self.account = "815602947203"
        self.prefix = "dns-smoke-" + uuid.uuid4().hex[:10]
        self.endpoint = f"http://127.0.0.1:{args.port}"
        self.dns_endpoint = f"127.0.0.1:{args.dns_port}"
        self.clients, self.owned = {}, {"lbs": [], "subnets": []}
        self.process = self.log = None
        self.data = {"source": "actual CLI, signed SDK, UDP/TCP DNS, native ALB HTTP/TLS", "account": self.account,
                     "calls": [], "observations": {}, "owned": self.owned, "cleanup": {}}
        self.save()

    def client(self, service, creds=None):
        if service not in self.clients:
            self.clients[service] = boto3.client(service, region_name=REGION, endpoint_url=self.endpoint,
                aws_access_key_id="test", aws_secret_access_key="test",
                config=Config(retries={"max_attempts": 0}, connect_timeout=5, read_timeout=30))
        return self.clients[service]

    def start(self):
        self.log = (self.state / "controller.log").open("ab")
        command = [str(self.args.binary.resolve()), "-listen", f"0.0.0.0:{self.args.port}", "-account-id", self.account,
                   "-database", str(self.state / "state.sqlite"), "-docker-host", "unix:///var/run/docker.sock",
                   "-elbv2-node-executable", str(self.args.elbv2_node_executable.resolve()), "-dns-listen", self.dns_endpoint]
        self.process = subprocess.Popen(command, stdout=self.log, stderr=subprocess.STDOUT)
        def ready():
            if self.process.poll() is not None:
                raise RuntimeError((self.state / "controller.log").read_text())
            try:
                return self.client("sts").get_caller_identity()["Account"] == self.account
            except Exception:
                return False
        self.wait("controller ready", ready, bool, 60)

    def answers(self, name):
        udp = query(self.dns_endpoint, name)
        tcp = query(self.dns_endpoint, name, tcp=True)
        assert udp == tcp, (udp, tcp)
        assert udp["status"] == "NOERROR", udp
        assert all(row["type"] == "A" and row["ttl"] == 60 for row in udp["records"]), udp
        return sorted(row["value"] for row in udp["records"])

    def get(self, client, url):
        try:
            with client.open(url, timeout=5) as response:
                return {"status": response.status, "body": response.read().decode()}
        except OSError:
            return None

    def run(self):
        self.start()
        o = self.owned
        o["vpc"] = self.call("vpc", "ec2", "create_vpc", CidrBlock="10.197.42.0/24")["Vpc"]["VpcId"]
        for index, cidr in enumerate(["10.197.42.0/26", "10.197.42.64/26", "10.197.42.128/26"]):
            o["subnets"].append(self.call("subnet-" + str(index), "ec2", "create_subnet", VpcId=o["vpc"],
                CidrBlock=cidr, AvailabilityZone=REGION + chr(ord("a") + index))["Subnet"]["SubnetId"])
        o["sg"] = self.call("sg", "ec2", "create_security_group", VpcId=o["vpc"], GroupName=self.prefix, Description=self.prefix)["GroupId"]
        self.call("ingress", "ec2", "authorize_security_group_ingress", GroupId=o["sg"],
                  IpPermissions=[{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
        for suffix in ("primary", "unrelated"):
            lb = self.call(suffix, "elbv2", "create_load_balancer", Name=self.prefix + "-" + suffix,
                          Type="application", Scheme="internal", Subnets=o["subnets"][:2], SecurityGroups=[o["sg"]])["LoadBalancers"][0]
            o["lbs"].append(lb["LoadBalancerArn"])
            if suffix == "primary":
                primary = lb
            else:
                unrelated = lb
        name = primary["DNSName"]
        try:
            ipaddress.ip_address(name)
        except ValueError:
            pass
        else:
            raise AssertionError("DNSName is still a literal address: " + name)
        self.data["observations"]["name"] = name
        arn = primary["LoadBalancerArn"]
        def fixed(status, body):
            return [{"Type": "fixed-response", "FixedResponseConfig": {"StatusCode": str(status), "ContentType": "text/plain", "MessageBody": body}}]
        listener = self.call("http-listener", "elbv2", "create_listener", LoadBalancerArn=arn, Protocol="HTTP", Port=80,
                             DefaultActions=fixed(421, "wrong hostname"))["Listeners"][0]
        self.call("hostname-route", "elbv2", "create_rule", ListenerArn=listener["ListenerArn"], Priority=1,
                  Conditions=[{"Field": "host-header", "HostHeaderConfig": {"Values": [name]}}], Actions=fixed(200, "hostname-http"))
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=alb-dns-smoke",
                        "-addext", "subjectAltName=DNS:" + name, "-keyout", str(self.state / "alb.key"),
                        "-out", str(self.state / "alb.crt")], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cert = self.call("certificate", "iam", "upload_server_certificate", ServerCertificateName=self.prefix,
                         CertificateBody=(self.state / "alb.crt").read_text(), PrivateKey=(self.state / "alb.key").read_text())["ServerCertificateMetadata"]
        o["certificate"] = self.prefix
        self.call("https-listener", "elbv2", "create_listener", LoadBalancerArn=arn, Protocol="HTTPS", Port=443,
                  Certificates=[{"CertificateArn": cert["Arn"]}], SslPolicy="ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
                  DefaultActions=fixed(200, "hostname-tls"))
        http = opener(self.dns_endpoint)
        https = opener(self.dns_endpoint, ssl.create_default_context(cafile=str(self.state / "alb.crt")))
        self.wait("HTTP hostname rule", lambda: self.get(http, "http://" + name), lambda row: row == {"status": 200, "body": "hostname-http"}, 180)
        self.wait("verified TLS hostname", lambda: self.get(https, "https://" + name), lambda row: row == {"status": 200, "body": "hostname-tls"}, 180)
        before = self.wait("both zone addresses", lambda: self.answers(name), lambda rows: len(rows) == 2, 120)
        aaaa = query(self.dns_endpoint, name, "AAAA")
        assert aaaa == {"status": "NOERROR", "records": []}, aaaa
        self.data["observations"]["before"] = {"addresses": before, "http": self.get(http, "http://" + name), "tls": self.get(https, "https://" + name), "aaaa": aaaa}
        self.save()
        self.stop()
        self.start()
        retained = self.client("elbv2").describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]
        assert retained["DNSName"] == name, retained
        assert self.answers(name) == before
        self.wait("retained verified TLS", lambda: self.get(https, "https://" + name), lambda row: row == {"status": 200, "body": "hostname-tls"}, 180)
        self.call("change-current-subnets", "elbv2", "set_subnets", LoadBalancerArn=arn, Subnets=o["subnets"][1:])
        after = self.wait("changed current addresses", lambda: self.answers(name), lambda rows: len(rows) == 2 and rows != before, 180)
        assert len(set(before) & set(after)) == 1, (before, after)
        assert self.client("elbv2").describe_load_balancers(LoadBalancerArns=[arn])["LoadBalancers"][0]["DNSName"] == name
        self.wait("changed-address HTTP", lambda: self.get(http, "http://" + name), lambda row: row == {"status": 200, "body": "hostname-http"}, 180)
        unrelated_before = self.answers(unrelated["DNSName"])
        self.call("delete-primary", "elbv2", "delete_load_balancer", LoadBalancerArn=arn)
        for tcp in (False, True):
            assert query(self.dns_endpoint, name, tcp=tcp) == {"status": "NXDOMAIN", "records": []}
        assert self.answers(unrelated["DNSName"]) == unrelated_before
        self.data["observations"]["transition"] = {"name": name, "before": before, "after": after, "deleted": "NXDOMAIN", "unrelated": unrelated_before}
        self.save()

    def cleanup(self):
        if self.process is None or self.process.poll() is not None:
            self.start()
        o = self.owned
        for arn in o["lbs"]:
            self.call("cleanup-lb", "elbv2", "delete_load_balancer", LoadBalancerArn=arn)
        if o.get("vpc"):
            self.wait("owned ENI teardown", lambda: self.client("ec2").describe_network_interfaces(Filters=[{"Name": "vpc-id", "Values": [o["vpc"]]}])["NetworkInterfaces"], lambda rows: not rows, 180)
        if o.get("certificate"):
            self.call("cleanup-certificate", "iam", "delete_server_certificate", ServerCertificateName=o["certificate"])
        if o.get("sg"):
            self.call("cleanup-sg", "ec2", "delete_security_group", GroupId=o["sg"])
        for subnet in o["subnets"]:
            self.call("cleanup-subnet", "ec2", "delete_subnet", SubnetId=subnet)
        if o.get("vpc"):
            self.call("cleanup-vpc", "ec2", "delete_vpc", VpcId=o["vpc"])
        self.data["cleanup"]["owned_resources_removed"] = True
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--elbv2-node-executable", type=Path, required=True)
    parser.add_argument("--state-directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18574)
    parser.add_argument("--dns-port", type=int, default=18575)
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
