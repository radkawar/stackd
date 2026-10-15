"""IAM credential lifecycles, genuine ChangePassword/STS/SSM consumers.

Console sessions, CodeCommit Git, SSH login and legacy X.509 request execution
are not implemented by the controller. Public-material crypto proofs below do
not substitute for those missing consumers. IAM-owned TLS deployment requires
the separately configured genuine ELBV2 relay, Docker and network/DNS topology.
"""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import struct
import sys
from urllib.request import ProxyHandler, Request, build_opener

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from local import REGION, client, expect_missing, local_endpoint, require

HTTP = build_opener(ProxyHandler({}))
PASSWORD_FIELDS = {
    "MinimumPasswordLength", "RequireSymbols", "RequireNumbers",
    "RequireUppercaseCharacters", "RequireLowercaseCharacters",
    "AllowUsersToChangePassword", "MaxPasswordAge", "PasswordReusePrevention", "HardExpiry",
}
IMPORT_GAPS = {
    "aws_iam_policy_attachment.credentials": "AWS 6.68.0 has no importer; exclusive bindings remain in the original state",
    "aws_iam_security_token_service_preferences.credentials": "AWS 6.68.0 has no importer and no-op deletion; captured before-image restored by cleanup",
    "aws_iam_group_membership.credentials": "AWS 6.68.0 has no importer; prerequisite membership remains in the original state",
}
CONSUMER_GAPS = {
    "aws_iam_user_login_profile": "VerifyPassword is internal; no console session owner. ChangePassword proves old-password verification, not console login.",
    "aws_iam_service_specific_credential": "VerifyServiceCredential is internal; no CodeCommit Git/Keyspaces/API-key protocol owner. List status is not authentication.",
    "aws_iam_user_ssh_key": "VerifySSHPublicKey is internal; no IAM-aware SSH/CodeCommit execution owner. RSA material proof is not SSH authentication.",
    "aws_iam_signing_certificate": "VerifySigningCertificate is internal; no legacy signed AWS-request owner. RSA material proof is not IAM certificate authentication.",
    "aws_iam_server_certificate": "Actual ELBV2Certificates TLS execution needs genuine ALB relay executable, Docker plus owned network/DNS topology; this module proves current certificate/key bytes only.",
    "aws_iam_security_token_service_preferences": "Loopback override selects regional STS. Summary/readback is covered; global-host legacy-token compatibility and opt-in region activation are not claimed.",
    "aws_iam_virtual_mfa_device": "Real virtual HMAC-SHA1 TOTP user sessions covered; root, hardware and FIDO devices are separate prerequisites.",
}


def save(root, name, value):
    path = Path(root) / name
    path.write_text(json.dumps(value, indent=2) + "\n")
    path.chmod(0o600)


def load(root, name, default=None):
    path = Path(root) / name
    return json.loads(path.read_text()) if path.exists() else default


def clock(endpoint, advance=None):
    data = None if advance is None else json.dumps({"advance": advance}).encode()
    request = Request(local_endpoint(endpoint) + "/_stackd/clock", data=data,
                      headers={"Content-Type": "application/json"})
    with HTTP.open(request, timeout=15) as response:
        value = json.load(response)
    return datetime.fromisoformat(value["time"].replace("Z", "+00:00"))


def signed(service, endpoint, key, secret, token=None):
    return boto3.Session(aws_access_key_id=key, aws_secret_access_key=secret,
                         aws_session_token=token, region_name=REGION).client(
        service, endpoint_url=local_endpoint(endpoint),
        config=Config(connect_timeout=3, read_timeout=60, proxies={},
                      retries={"max_attempts": 0}))


def rejected(call, codes, **kwargs):
    try:
        call(**kwargs)
    except ClientError as error:
        require(error.response["Error"]["Code"] in codes, str(error))
    else:
        raise RuntimeError(f"Rejected operation unexpectedly succeeded: {call.__name__}")


def prepare(root):
    """Generate only owned real keys. IAM, not Terraform, generates the MFA seed."""
    root = Path(root)
    directory = root / "credential-material"
    directory.mkdir(mode=0o700)
    now = datetime.now(timezone.utc)
    material = {}
    for purpose in ("server", "signing", "ssh"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private = key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
        path = directory / (purpose + "-key.pem")
        path.write_bytes(private)
        path.chmod(0o600)
        if purpose == "ssh":
            public = key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                                   serialization.PublicFormat.OpenSSH).decode()
            material["ssh_public_key"] = public
            (directory / "ssh.pub").write_text(public + "\n")
            continue
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                               "localhost" if purpose == "server" else "owned-local-signing")])
        certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                       .public_key(key.public_key()).serial_number(x509.random_serial_number())
                       .not_valid_before(now - timedelta(days=1))
                       .not_valid_after(now + timedelta(days=30))
                       .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True))
        if purpose == "server":
            certificate = certificate.add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        pem = certificate.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
        (directory / (purpose + "-certificate.pem")).write_text(pem)
        material[purpose + "_certificate"] = pem
        if purpose == "server":
            material["server_private_key"] = private.decode()
    # No injectable seed exists on aws_iam_virtual_mfa_device. The authenticator
    # consumes the genuine create-only Base32StringSeed output at enrollment.
    save(root, "credential-authenticator.json", {"algorithm": "HMAC-SHA1", "digits": 6, "period": 30})
    save(root, "credential-consumer-gaps.json", {"consumer": CONSUMER_GAPS, "import": IMPORT_GAPS})
    return {"credential_material": material}


def capture(endpoint, root):
    """Run once before apply, only inside the runner's private owned controller."""
    require((Path(root) / "stackd.sqlite").is_file(), "Credential globals require the private controller database")
    require(not (Path(root) / "credential-before.json").exists(), "Credential before-image already captured")
    iam = client("iam", endpoint)
    aliases = iam.list_account_aliases()["AccountAliases"]
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError as error:
        require(error.response["Error"]["Code"] == "NoSuchEntity", str(error))
        policy = None
    version = iam.get_account_summary()["SummaryMap"]["GlobalEndpointTokenVersion"]
    save(root, "credential-before.json", {"aliases": aliases, "password_policy": policy, "token_version": version})
    # AWS permits only one alias. Remove a captured alias only in this uniquely
    # owned controller and restore it after the fixture's own alias is destroyed.
    for alias in aliases:
        iam.delete_account_alias(AccountAlias=alias)


def totp(seed, step):
    digest = hmac.new(base64.b32decode(seed + "=" * (-len(seed) % 8)),
                      struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 15
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff
    return f"{value % 1000000:06d}"


def retained_material(out, root):
    """Native import cannot recover secrets; retain original local create outputs."""
    cached = load(root, "credential-secrets.json", {})
    for identity, secret_fields in (("key", ("secret",)), ("denied_key", ("denied_secret",)),
                                    ("service_id", ("service_secret",)), ("mfa_serial", ("mfa_seed",))):
        record = cached.get(out[identity], {})
        for field in secret_fields:
            if out.get(field):
                record[field] = out[field]
            require(record.get(field), f"Cannot recover create-only {field}; retain original private fixture outputs before import")
            out[field] = record[field]
        cached[out[identity]] = record
    save(root, "credential-secrets.json", cached)
    return out


def verify(endpoint, out, revision, root):
    out = retained_material(dict(out), root)
    iam = client("iam", endpoint)
    require(iam.get_login_profile(UserName=out["user"])["LoginProfile"]["PasswordResetRequired"] is False,
            "Native login-profile default/reset state changed across import or reopen")
    require(iam.list_account_aliases()["AccountAliases"] == [out["alias"]], "Account alias differs from applied revision")
    policy = iam.get_account_password_policy()["PasswordPolicy"]
    require(policy["MinimumPasswordLength"] == (16 if revision == "v1" else 24)
            and policy["PasswordReusePrevention"] == (3 if revision == "v1" else 5)
            and policy["MaxPasswordAge"] == (90 if revision == "v1" else 60)
            and policy["HardExpiry"] == (revision == "v2")
            and all(policy[field] for field in ("RequireSymbols", "RequireNumbers", "RequireUppercaseCharacters", "RequireLowercaseCharacters", "AllowUsersToChangePassword")),
            "Current password policy revision was not retained")
    require(iam.get_account_summary()["SummaryMap"]["GlobalEndpointTokenVersion"] == (1 if revision == "v1" else 2),
            "STS account preference did not update")
    user_iam = signed("iam", endpoint, out["key"], out["secret"])
    profile = iam.get_login_profile(UserName=out["user"])["LoginProfile"]
    password = load(root, "credential-password.json")
    created = profile["CreateDate"].isoformat()
    if password is None or password["created"] != created:
        require(out.get("password"), "Imported login profile has no recoverable password; retain original local creation outputs")
        password = {"created": created, "current": out["password"]}
    old = password["current"]
    rejected(user_iam.change_password, {"PasswordPolicyViolation"}, OldPassword=old, NewPassword="short")
    rejected(user_iam.change_password, {"AccessDenied"}, OldPassword="definitely-not-the-password", NewPassword="Aa1!" + secrets.token_hex(20))
    # A real ChangePassword verifies the previous hash and commits a new hash.
    # It is NOT a console login or an IAM password-to-access-key exchange.
    new = "Aa1!" + secrets.token_hex(20)
    user_iam.change_password(OldPassword=old, NewPassword=new)
    save(root, "credential-password.json", {"created": created, "current": new})
    rejected(user_iam.change_password, {"AccessDenied"}, OldPassword=old, NewPassword="Bb2!" + secrets.token_hex(20))
    rejected(user_iam.change_password, {"PasswordPolicyViolation"}, OldPassword=new, NewPassword=old)
    require(not iam.get_login_profile(UserName=out["user"])["LoginProfile"]["PasswordResetRequired"], "Changed password still requires reset")

    consumer = signed("ssm", endpoint, out["key"], out["secret"])
    denied = signed("ssm", endpoint, out["denied_key"], out["denied_secret"])
    require(consumer.get_parameter(Name=out["parameter"])["Parameter"]["Value"] == revision, "Attachment did not authorize actual SSM value")
    rejected(denied.get_parameter, {"AccessDeniedException"}, Name=out["parameter"])
    entities = iam.list_entities_for_policy(PolicyArn=out["policy_arn"])
    require({item["GroupName"] for item in entities["PolicyGroups"]} == ({out["group"]} if revision == "v1" else set())
            and {item["UserName"] for item in entities["PolicyUsers"]} == ({out["user"]} if revision == "v2" else set())
            and {item["RoleName"] for item in entities["PolicyRoles"]} == {out["role"]}, "Exclusive policy attachment update differs")
    kind = "group" if revision == "v1" else "user"
    principal = {kind.capitalize() + "Name": out[kind], "PolicyArn": out["policy_arn"]}
    getattr(iam, "detach_" + kind + "_policy")(**principal)
    try:
        rejected(consumer.get_parameter, {"AccessDeniedException"}, Name=out["parameter"])
    finally:
        getattr(iam, "attach_" + kind + "_policy")(**principal)
    sts = signed("sts", endpoint, out["key"], out["secret"])
    session = sts.assume_role(RoleArn=out["role_arn"], RoleSessionName="credential-consumer")["Credentials"]
    role = signed("ssm", endpoint, session["AccessKeyId"], session["SecretAccessKey"], session["SessionToken"])
    require(role.get_parameter(Name=out["parameter"])["Parameter"]["Value"] == revision, "Role attachment did not authorize real session")
    iam.detach_role_policy(RoleName=out["role"], PolicyArn=out["policy_arn"])
    try:
        rejected(role.get_parameter, {"AccessDeniedException"}, Name=out["parameter"])
    finally:
        iam.attach_role_policy(RoleName=out["role"], PolicyArn=out["policy_arn"])
    rejected(consumer.get_parameter, {"AccessDeniedException"}, Name=out["mfa_parameter"])
    _verify_mfa(endpoint, out, revision, root, iam, sts)
    _verify_public_material(iam, out, revision, root)
    print(f"Credential consumers {revision}: actual password change/history rejection, current user/group/role policy authority, TOTP STS session and MFA-only SSM bytes; certificate/key material integrity only", flush=True)


def _verify_mfa(endpoint, out, revision, root, iam, sts):
    seed = out["mfa_seed"]
    # Some SDK/provider blob representations are base64; the native provider
    # currently exposes literal ASCII base32, as its implementation documents.
    require(seed and all(char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for char in seed), "MFA output was not a genuine base32 seed")
    assigned = iam.list_mfa_devices(UserName=out["user"])["MFADevices"]
    if not any(device["SerialNumber"] == out["mfa_serial"] for device in assigned):
        now = clock(endpoint)
        step = int(now.timestamp()) // 30
        iam.enable_mfa_device(UserName=out["user"], SerialNumber=out["mfa_serial"],
                              AuthenticationCode1=totp(seed, step - 1), AuthenticationCode2=totp(seed, step))
        clock(endpoint, "11s")  # Existing IAM -> STS authority propagation, not wall time.
    devices = iam.list_virtual_mfa_devices(AssignmentStatus="Assigned")["VirtualMFADevices"]
    require(any(device["SerialNumber"] == out["mfa_serial"] and device["User"]["UserName"] == out["user"] for device in devices), "MFA enrollment lost immutable user binding")
    tags = iam.list_mfa_device_tags(SerialNumber=out["mfa_serial"])["Tags"]
    require({tag["Key"]: tag["Value"] for tag in tags}["Revision"] == revision, "MFA tag revision was not retained")
    # Fresh counter on every invocation (including reopen/import) avoids replay.
    step = int(clock(endpoint, "30s").timestamp()) // 30
    code = totp(seed, step)
    session = sts.get_session_token(SerialNumber=out["mfa_serial"], TokenCode=code, DurationSeconds=900)["Credentials"]
    rejected(sts.get_session_token, {"AccessDenied", "InvalidAuthenticationCode"}, SerialNumber=out["mfa_serial"], TokenCode=code, DurationSeconds=900)
    rejected(signed("sts", endpoint, out["denied_key"], out["denied_secret"]).get_session_token,
             {"AccessDenied", "InvalidAuthenticationCode"}, SerialNumber=out["mfa_serial"], TokenCode=code, DurationSeconds=900)
    mfa = signed("ssm", endpoint, session["AccessKeyId"], session["SecretAccessKey"], session["SessionToken"])
    require(mfa.get_parameter(Name=out["mfa_parameter"])["Parameter"]["Value"] == revision, "MFA session did not deliver real SSM bytes")
    name = "credential-current-mfa-deny"
    iam.put_user_policy(UserName=out["user"], PolicyName=name, PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "ssm:GetParameter", "Resource": "*"}]}))
    try:
        rejected(mfa.get_parameter, {"AccessDeniedException"}, Name=out["mfa_parameter"])
    finally:
        iam.delete_user_policy(UserName=out["user"], PolicyName=name)
    require(mfa.get_parameter(Name=out["mfa_parameter"])["Parameter"]["Value"] == revision, "Existing MFA session failed restored current authority")
    iam.deactivate_mfa_device(UserName=out["user"], SerialNumber=out["mfa_serial"])
    try:
        step = int(clock(endpoint, "41s").timestamp()) // 30
        rejected(sts.get_session_token, {"AccessDenied"}, SerialNumber=out["mfa_serial"],
                 TokenCode=totp(seed, step), DurationSeconds=900)
    finally:
        # Re-enrollment uses a newer consecutive pair, preserving replay state.
        step = int(clock(endpoint, "30s").timestamp()) // 30
        iam.enable_mfa_device(UserName=out["user"], SerialNumber=out["mfa_serial"],
                              AuthenticationCode1=totp(seed, step - 1), AuthenticationCode2=totp(seed, step))
        clock(endpoint, "11s")


def _verify_public_material(iam, out, revision, root):
    directory = Path(root) / "credential-material"
    expected_status = "Active" if revision == "v1" else "Inactive"
    server = iam.get_server_certificate(ServerCertificateName=out["server_name"])["ServerCertificate"]
    metadata = server["ServerCertificateMetadata"]
    require(metadata["Arn"] == out["server_arn"] and metadata["ServerCertificateId"] == out["server_id"]
            and metadata["Path"] == f"/credentials/{revision}/", "Server certificate rename/path update lost identity")
    require("PrivateKey" not in server, "IAM leaked server private key")
    previous = load(root, "credential-server-identity.json")
    if previous is not None:
        require(previous["id"] == metadata["ServerCertificateId"], "Rename replaced immutable server certificate identity")
        if previous["name"] != out["server_name"]:
            expect_missing(iam.get_server_certificate, {"NoSuchEntity"}, ServerCertificateName=previous["name"])
    save(root, "credential-server-identity.json", {"id": metadata["ServerCertificateId"], "name": out["server_name"]})
    tags = iam.list_server_certificate_tags(ServerCertificateName=out["server_name"])["Tags"]
    require({tag["Key"]: tag["Value"] for tag in tags}["Revision"] == revision, "Server tags did not update")
    certificates = iam.list_signing_certificates(UserName=out["user"])["Certificates"]
    signing = next(item for item in certificates if item["CertificateId"] == out["signing_id"])
    require(signing["Status"] == expected_status, "Signing certificate status did not update")
    for purpose, body in (("server", server["CertificateBody"]), ("signing", signing["CertificateBody"])):
        current = x509.load_pem_x509_certificate(body.encode())
        prepared = x509.load_pem_x509_certificate((directory / (purpose + "-certificate.pem")).read_bytes())
        require(current.fingerprint(hashes.SHA256()) == prepared.fingerprint(hashes.SHA256()), "Current certificate bytes differ from actual prepared certificate")
        key = serialization.load_pem_private_key((directory / (purpose + "-key.pem")).read_bytes(), password=None)
        payload = (purpose + ":" + revision + ":" + secrets.token_hex(16)).encode()
        signature = key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
        current.public_key().verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
        try:
            current.public_key().verify(signature, payload + b"tampered", padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            pass
        else:
            raise RuntimeError("Tampered certificate signature verified")
    ssh = iam.get_ssh_public_key(UserName=out["user"], SSHPublicKeyId=out["ssh_id"], Encoding="SSH")["SSHPublicKey"]
    require(ssh["Status"] == expected_status, "SSH key status did not update")
    public = serialization.load_ssh_public_key(ssh["SSHPublicKeyBody"].encode())
    key = serialization.load_pem_private_key((directory / "ssh-key.pem").read_bytes(), password=None)
    require(public.public_numbers() == key.public_key().public_numbers(), "IAM SSH public key differs from owned key")
    payload = ("ssh-material:" + revision + ":" + secrets.token_hex(16)).encode()
    signature = key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    public.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
    try:
        public.verify(signature, payload + b"tampered", padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        pass
    else:
        raise RuntimeError("Tampered SSH public-material signature verified")
    wire = base64.b64decode(ssh["SSHPublicKeyBody"].split()[1], validate=True)
    fingerprint = ":".join(f"{byte:02x}" for byte in hashlib.md5(wire).digest())
    require(ssh["Fingerprint"] == fingerprint, "IAM SSH wire fingerprint differs")
    pem = iam.get_ssh_public_key(UserName=out["user"], SSHPublicKeyId=out["ssh_id"], Encoding="PEM")["SSHPublicKey"]
    require(serialization.load_pem_public_key(pem["SSHPublicKeyBody"].encode()).public_numbers() == public.public_numbers(), "SSH/PEM conversion changed key")
    records = iam.list_service_specific_credentials(UserName=out["user"], ServiceName="codecommit.amazonaws.com")["ServiceSpecificCredentials"]
    service = next(item for item in records if item["ServiceSpecificCredentialId"] == out["service_id"])
    require(service["Status"] == expected_status and service["ServiceUserName"] == out["service_login"], "Service credential readback/status changed")
    require(not {"ServicePassword", "ServiceCredentialSecret"}.intersection(service), "IAM list leaked create-only service secret")


def verify_deleted(endpoint, out, root):
    iam = client("iam", endpoint)
    require(not iam.list_account_aliases()["AccountAliases"], "Fixture alias survived destroy")
    expect_missing(iam.get_account_password_policy, {"NoSuchEntity"})
    expect_missing(iam.get_server_certificate, {"NoSuchEntity"}, ServerCertificateName=out["server_name"])
    require(not any(device["SerialNumber"] == out["mfa_serial"] for device in iam.list_virtual_mfa_devices()["VirtualMFADevices"]), "Virtual MFA device survived destroy")
    for name in (out["user"], out["denied_user"]):
        expect_missing(iam.get_user, {"NoSuchEntity"}, UserName=name)
    expect_missing(iam.get_group, {"NoSuchEntity"}, GroupName=out["group"])
    expect_missing(iam.get_role, {"NoSuchEntity"}, RoleName=out["role"])
    expect_missing(iam.get_policy, {"NoSuchEntity"}, PolicyArn=out["policy_arn"])
    for name in (out["parameter"], out["mfa_parameter"]):
        expect_missing(client("ssm", endpoint).get_parameter, {"ParameterNotFound"}, Name=name)
    cached = load(root, "credential-secrets.json", {})
    secret = out.get("secret") or cached.get(out["key"], {}).get("secret")
    require(secret, "Retain original secret to prove deleted key rejection")
    rejected(signed("sts", endpoint, out["key"], secret).get_caller_identity,
             {"InvalidClientTokenId", "UnrecognizedClientException"})


def cleanup(endpoint, out, root):
    before = load(root, "credential-before.json")
    require(before is not None, "Cannot restore globals without captured before-image")
    iam = client("iam", endpoint)
    require(not iam.list_account_aliases()["AccountAliases"], "Refusing to restore over an undeleted fixture alias")
    for alias in before["aliases"]:
        iam.create_account_alias(AccountAlias=alias)
    if before["password_policy"] is not None:
        iam.update_account_password_policy(**{key: value for key, value in before["password_policy"].items() if key in PASSWORD_FIELDS})
    else:
        try:
            iam.delete_account_password_policy()
        except ClientError as error:
            require(error.response["Error"]["Code"] == "NoSuchEntity", str(error))
    iam.set_security_token_service_preferences(GlobalEndpointTokenVersion=f"v{before['token_version']}Token")
    clock(endpoint, "11s")
    require(iam.list_account_aliases()["AccountAliases"] == before["aliases"], "Captured alias not restored")
    require(iam.get_account_summary()["SummaryMap"]["GlobalEndpointTokenVersion"] == before["token_version"], "Captured token version not restored")
    if before["password_policy"] is None:
        expect_missing(iam.get_account_password_policy, {"NoSuchEntity"})
    else:
        require(iam.get_account_password_policy()["PasswordPolicy"] == before["password_policy"], "Captured password policy not restored")


def imports(resources):
    result = {}
    for resource in resources:
        address, kind, value = resource["address"], resource["type"], resource["values"]
        if address.split(".")[-1] not in ("credentials", "credentials_denied", "credentials_mfa") or address in IMPORT_GAPS:
            continue
        if kind == "aws_iam_server_certificate":
            identifier = value["name"]
        elif kind == "aws_iam_user_ssh_key":
            identifier = f"{value['username']}:{value['ssh_public_key_id']}:{value['encoding']}"
        elif kind == "aws_iam_user_login_profile":
            identifier = value["user"]
        elif kind in {"aws_iam_account_alias", "aws_iam_account_password_policy", "aws_iam_user", "aws_iam_access_key", "aws_iam_group", "aws_iam_role", "aws_iam_policy", "aws_iam_user_policy", "aws_iam_signing_certificate", "aws_iam_service_specific_credential", "aws_iam_virtual_mfa_device", "aws_ssm_parameter"}:
            identifier = value["id"]
        else:
            continue
        result[address] = identifier
    return result
