"""Real IAM certificate deployment through owned native ALB TLS sockets.

Reuse the existing explicit DNS client. Host, SNI and hostname verification stay
unchanged; there are no system resolver edits or metadata-only network substitutes.
"""
from datetime import datetime, timedelta, timezone
import http.client
import ipaddress
import json
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from local import client, environment, expect_missing, require
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from dns_http_client import create_connection, query


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def prepare(root):
    directory = root / "tls"
    directory.mkdir(mode=0o700)
    octet = secrets.randbelow(19) + 221
    return {"tls_vpc_cidr": f"10.{octet}.0.0/16", "tls_subnet_cidrs": [f"10.{octet}.1.0/24", f"10.{octet}.2.0/24"],
            "tls_ready": False}


def configure(root, docker_host, dns_endpoint):
    save(root / "tls/consumer.json", {"docker_host": docker_host, "dns_endpoint": dns_endpoint})


def issue(root, hostname):
    require(hostname and hostname.endswith(".amazonaws.com"), "Use the owned ALB's actual DNS name, not an arbitrary issuer")
    key = serialization.load_pem_private_key((root / "credential-material/server-key.pem").read_bytes(), password=None)
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Owned identity TLS application")])
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
                   .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                   .sign(key, hashes.SHA256()))
    pem = certificate.public_bytes(serialization.Encoding.PEM)
    path = root / "tls/consumer-cert.pem"
    path.write_bytes(pem)
    path.chmod(0o600)
    return {"tls_certificate_body": pem.decode(), "tls_ready": True}


def docker(root, *arguments):
    config = json.loads((root / "tls/consumer.json").read_text())
    return subprocess.check_output(["docker", "--host", config["docker_host"], *arguments], env=environment(), text=True)


def request(root, hostname, context, server_hostname=None):
    config = json.loads((root / "tls/consumer.json").read_text())
    with create_connection(config["dns_endpoint"], (hostname, 8443), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=server_hostname or hostname) as stream:
            certificate = stream.getpeercert(binary_form=True)
            protocol = stream.version()
            stream.sendall(f"GET /actual-iam-certificate HTTP/1.1\r\nHost: {hostname}:8443\r\nConnection: close\r\n\r\n".encode())
            response = http.client.HTTPResponse(stream)
            try:
                response.begin()
                return response.status, response.read(), certificate, protocol
            finally:
                response.close()


def verify(endpoint, out, revision, root):
    iam, elb, ec2 = (client(name, endpoint) for name in ("iam", "elbv2", "ec2"))
    config = json.loads((root / "tls/consumer.json").read_text())
    owned = iam.get_server_certificate(ServerCertificateName=out["certificate_name"])["ServerCertificate"]
    metadata = owned["ServerCertificateMetadata"]
    require(metadata["ServerCertificateId"] == out["certificate_id"] and metadata["Arn"] == out["certificate_arn"],
            "Live certificate deployment lost its current immutable IAM identity")
    certificate = x509.load_pem_x509_certificate(owned["CertificateBody"].encode())
    expected_der = certificate.public_bytes(serialization.Encoding.DER)
    require(expected_der == x509.load_pem_x509_certificate((root / "tls/consumer-cert.pem").read_bytes()).public_bytes(serialization.Encoding.DER),
            "Current IAM owner returned different TLS public material")
    context = ssl.create_default_context(cafile=str(root / "tls/consumer-cert.pem"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    deadline = time.monotonic() + 180
    while True:
        try:
            answer = query(config["dns_endpoint"], out["dns_name"])
            require(answer["status"] == "NOERROR", "Owned authoritative DNS did not publish the actual ALB")
            addresses = [row["value"] for row in answer["records"] if row["type"] == "A"]
            require(addresses, "Owned native ALB has no actual DNS addresses")
            for address in addresses:
                ipaddress.IPv4Address(address)
            status, body, deployed, protocol = request(root, out["dns_name"], context)
            require(status == 200 and body == f"real-iam-tls-{revision}".encode(), "Actual TLS relay did not serve current listener bytes")
            require(deployed == expected_der and protocol in {"TLSv1.2", "TLSv1.3"}, "Native TLS did not use the current IAM-owned certificate/policy")
            break
        except (OSError, RuntimeError) as error:
            require(time.monotonic() < deadline, f"Actual IAM TLS consumer did not settle: {error}")
            time.sleep(0.5)
    for invalid in ("wrong.example.invalid",):
        try:
            request(root, out["dns_name"], context, server_hostname=invalid)
        except ssl.SSLCertVerificationError:
            pass
        else:
            raise RuntimeError("Actual native TLS accepted a certificate for the wrong hostname")
    try:
        request(root, out["dns_name"], ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    except ssl.SSLCertVerificationError:
        pass
    else:
        raise RuntimeError("Actual native TLS accepted an untrusted signing authority")
    expect_missing(iam.delete_server_certificate, {"DeleteConflict"}, ServerCertificateName=out["certificate_name"])
    listeners = elb.describe_listeners(ListenerArns=[out["listener"]])["Listeners"]
    require(listeners[0]["Certificates"][0]["CertificateArn"] == out["certificate_arn"], "Listener retained a stale certificate ARN after IAM rename")
    containers = docker(root, "ps", "--all", "--quiet", "--filter", "label=stackd.elbv2.load-balancer=" + out["load_balancer"]).split()
    require(containers, "Actual TLS succeeded without any retained owned native ALB process")
    for identifier in containers:
        inspected = json.loads(docker(root, "inspect", identifier))[0]
        require(inspected["Config"]["Labels"]["stackd.elbv2.load-balancer"] == out["load_balancer"] and
                inspected["State"]["Running"] and inspected["State"]["Pid"] > 0,
                "ALB container is not actually running under the current ownership")
    deletion = iam.delete_service_linked_role(RoleName="AWSServiceRoleForElasticLoadBalancing")["DeletionTaskId"]
    deadline = time.monotonic() + 30
    while True:
        status = iam.get_service_linked_role_deletion_status(DeletionTaskId=deletion)
        if status["Status"] not in {"NOT_STARTED", "IN_PROGRESS"}:
            break
        require(time.monotonic() < deadline, "Current linked-role usage task did not complete")
        time.sleep(0.1)
    resources = {resource for row in status.get("Reason", {}).get("RoleUsageList", []) for resource in row.get("Resources", [])}
    require(status["Status"] == "FAILED" and out["load_balancer"] in resources,
            "The genuine ALB/native-network owner did not fence its service-linked role")
    checkpoint = root / "tls/evidence.json"
    previous = json.loads(checkpoint.read_text()) if checkpoint.exists() else None
    if previous is not None:
        require(previous["certificate_id"] == out["certificate_id"], "Rename/import/reopen replaced the immutable deployed certificate")
        require(previous["dns_name"] == out["dns_name"], "Import/reopen fabricated a different ALB identity")
    save(checkpoint, {"certificate_id": out["certificate_id"], "dns_name": out["dns_name"], "addresses": addresses,
                      "containers": sorted(set(containers) | set(previous.get("containers", []) if previous else [])),
                      "revision": revision, "tls_protocol": protocol})
    print(f"TLS complete: {revision}; actual authoritative DNS/native ALB/verified SNI, IAM certificate bytes and current deletion fence", flush=True)


def imports(resources):
    result = {}
    for item in resources:
        if item["address"].split(".")[-1].split("[")[0] != "identity_tls":
            continue
        values = item["values"]
        identifier = values["name"] if item["type"] == "aws_iam_server_certificate" else values["id"]
        result[item["address"]] = identifier
    return result


def verify_deleted(endpoint, out, root):
    expect_missing(client("elbv2", endpoint).describe_load_balancers, {"LoadBalancerNotFound"}, LoadBalancerArns=[out["load_balancer"]])
    expect_missing(client("elbv2", endpoint).describe_listeners, {"ListenerNotFound"}, ListenerArns=[out["listener"]])
    expect_missing(client("iam", endpoint).get_server_certificate, {"NoSuchEntity"}, ServerCertificateName=out["certificate_name"])
    ec2 = client("ec2", endpoint)
    expect_missing(ec2.describe_vpcs, {"InvalidVpcID.NotFound"}, VpcIds=[out["vpc"]])
    for subnet in out["subnets"]:
        expect_missing(ec2.describe_subnets, {"InvalidSubnetID.NotFound"}, SubnetIds=[subnet])
    expect_missing(ec2.describe_security_groups, {"InvalidGroup.NotFound"}, GroupIds=[out["group"]])
    require(not ec2.describe_network_interfaces(Filters=[{"Name": "vpc-id", "Values": [out["vpc"]]}])["NetworkInterfaces"], "Managed native ALB ENIs remain")
    require(not docker(root, "ps", "--all", "--quiet", "--filter", "label=stackd.elbv2.load-balancer=" + out["load_balancer"]).strip(),
            "Owned native ALB process survived destruction")
    previous = json.loads((root / "tls/evidence.json").read_text())
    running = set(docker(root, "ps", "--all", "--quiet").split())
    require(not running.intersection(previous["containers"]), "A retained owned relay container survived deletion/reopen")
    for address in previous["addresses"]:
        try:
            with socket.create_connection((address, 8443), timeout=2):
                raise RuntimeError("Remembered native ALB endpoint still accepts connections after destroy")
        except OSError:
            pass
    config = json.loads((root / "tls/consumer.json").read_text())
    answer = query(config["dns_endpoint"], out["dns_name"])
    require(not [row for row in answer["records"] if row["type"] == "A"], "Deleted ALB remains published in current authoritative DNS")
    print("TLS teardown complete: actual relay containers/old sockets/DNS/ENIs absent, IAM certificate and network owners deleted", flush=True)


def wait_retired(endpoint, out, root):
    """Wait for actual native retirement before identity-role/certificate deletion."""
    ec2 = client("ec2", endpoint)
    deadline = time.monotonic() + 180
    while True:
        processes = docker(root, "ps", "--all", "--quiet", "--filter",
                           "label=stackd.elbv2.load-balancer=" + out["load_balancer"]).split()
        interfaces = ec2.describe_network_interfaces(Filters=[{"Name": "vpc-id", "Values": [out["vpc"]]}])["NetworkInterfaces"]
        if not processes and not interfaces:
            return
        require(time.monotonic() < deadline, "Actual ALB retirement still owns native processes or managed interfaces")
        time.sleep(0.5)
