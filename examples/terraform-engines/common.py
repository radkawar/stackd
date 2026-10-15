"""Small native-client helpers. Controller ownership stays in examples/local.py."""

import shutil
import socket
import subprocess

from local import client, environment, require

VALKEY_IMAGE = "valkey/valkey@sha256:1cb6b20b70d927560cc4cc5397b5f045e74aa603ff7696274778880bb6fadc75"
KAFKA_IMAGE = "apache/kafka@sha256:ed74d7d115968d5e8b00ba6822ac6a384cbaaf54ca38991828647000d7089b68"


def command(argv, **kwargs):
    kwargs.setdefault("check", True)
    kwargs.setdefault("text", True)
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("env", environment())
    return subprocess.run([str(value) for value in argv], **kwargs)


def inspect_image(args, image):
    require(shutil.which("docker"), "Install the Docker CLI and prepare the documented local Engine first")
    require(args.docker_host.startswith("unix:///"), "Native engine examples require an explicit local Unix Docker socket")
    command(["docker", "--host", args.docker_host, "image", "inspect", image])


def tls(root):
    cert, key = root / "local.crt", root / "local.key"
    require(shutil.which("openssl"), "Install OpenSSL first")
    require(cert.exists() == key.exists(), "Incomplete retained TLS material; do not replace keys under native resources")
    if not cert.exists():
        command(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-sha256", "-nodes", "-days", "7",
                 "-keyout", key, "-out", cert, "-subj", "/CN=stackd-terraform-engines",
                 "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
                 "-addext", "basicConstraints=critical,CA:TRUE",
                 "-addext", "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign",
                 "-addext", "extendedKeyUsage=serverAuth"])
        key.chmod(0o600)
    return cert, key


def password(root, name="native-password"):
    path = root / name
    require(path.is_file(), f"Missing owned password file: {path}")
    return path.read_text().strip()


def denied(call):
    from botocore.exceptions import ClientError
    try:
        call()
    except ClientError as error:
        code = error.response["Error"]["Code"]
        require("AccessDenied" in code or code in {"Forbidden", "UnauthorizedOperation"}, str(error))
    else:
        raise RuntimeError("Caller without authority was allowed")


def unprivileged(service, endpoint, root):
    """Create an owned no-policy IAM user; caller deletes it in the same API scope."""
    import boto3
    from botocore.config import Config
    iam = client("iam", endpoint)
    name = root.name[-40:] + "-denied"
    iam.create_user(UserName=name)
    try:
        key = iam.create_access_key(UserName=name)["AccessKey"]
    except BaseException:
        iam.delete_user(UserName=name)
        raise
    native = boto3.client(service, endpoint_url=endpoint, region_name="us-east-1",
                          aws_access_key_id=key["AccessKeyId"], aws_secret_access_key=key["SecretAccessKey"],
                          config=Config(proxies={}, retries={"max_attempts": 0}, connect_timeout=3, read_timeout=15))
    return native, (iam, name, key["AccessKeyId"])


def delete_unprivileged(owned):
    iam, name, access_key = owned
    iam.delete_access_key(UserName=name, AccessKeyId=access_key)
    iam.delete_user(UserName=name)


def closed(address, port):
    """Require the old native listener to close, not merely a missing API row."""
    try:
        connection = socket.create_connection((address, int(port)), timeout=2)
    except ConnectionRefusedError:
        return
    connection.close()
    raise RuntimeError(f"Deleted native engine still accepts TCP at {address}:{port}")
