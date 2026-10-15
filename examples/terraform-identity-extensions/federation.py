"""Owned loopback TLS issuer, real XMLDSig/JWT consumers and federation authority."""

import base64
import contextlib
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import ssl
import threading
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.x509.oid import NameOID
from lxml import etree

from local import client, expect_missing, local_endpoint, require

SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"
METADATA = "urn:oasis:names:tc:SAML:2.0:metadata"
DS = "http://www.w3.org/2000/09/xmldsig#"
C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
RECIPIENT = "https://signin.aws.amazon.com/saml"
HTTP = build_opener(ProxyHandler({}))


def _private(path, data):
    with Path(path).open("xb") as stream:
        os.chmod(path, 0o600)
        stream.write(data)


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _key(root, revision):
    return serialization.load_pem_private_key(
        (Path(root) / "federation" / f"signing-{revision}.pem").read_bytes(), password=None)


def _jwk(key, revision):
    public = key.public_key().public_numbers()
    def integer(value):
        return _b64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))
    # Retained native AWS captures reject key_ops, even ["verify"].
    return {"kid": revision, "kty": "RSA", "alg": "RS256", "use": "sig",
            "n": integer(public.n), "e": integer(public.e)}


def _child(parent, namespace, name, text=None, **attributes):
    child = etree.SubElement(parent, f"{{{namespace}}}{name}", **attributes)
    child.text = text
    return child


def _metadata(issuer, certificate, revision):
    root = etree.Element(f"{{{METADATA}}}EntityDescriptor", nsmap={"md": METADATA, "ds": DS},
                         entityID=issuer, ID=f"_metadata-{revision}")
    idp = _child(root, METADATA, "IDPSSODescriptor",
                 protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol")
    info = _child(_child(idp, METADATA, "KeyDescriptor", use="signing"), DS, "KeyInfo")
    _child(_child(info, DS, "X509Data"), DS, "X509Certificate",
           base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode())
    _child(idp, METADATA, "SingleSignOnService", Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
           Location=issuer + "/saml")
    return etree.tostring(root, encoding="utf-8", xml_declaration=True)


def prepare(root):
    """Create private local artifacts; never start a process or contact an issuer."""
    directory = Path(root) / "federation"
    directory.mkdir(mode=0o700)
    issuer = "https://127.0.0.1/" + uuid.uuid4().hex
    now = datetime.now(timezone.utc)
    tls_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "owned local federation CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(tls_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=7))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .sign(tls_key, hashes.SHA256()))
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])).issuer_name(ca_name)
            .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=7))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(tls_key, hashes.SHA256()))
    _private(directory / "issuer_ca.pem", ca.public_bytes(serialization.Encoding.PEM))
    _private(directory / "issuer_chain.pem", leaf.public_bytes(serialization.Encoding.PEM) + ca.public_bytes(serialization.Encoding.PEM))
    _private(directory / "issuer_key.pem", leaf_key.private_bytes(serialization.Encoding.PEM,
             serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    keys = []
    for revision in ("v1", "v2", "wrong"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _private(directory / f"signing-{revision}.pem", key.private_bytes(serialization.Encoding.PEM,
                 serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"local SAML {revision}")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=7))
                .sign(key, hashes.SHA256()))
        _private(directory / f"signing-{revision}.crt", cert.public_bytes(serialization.Encoding.PEM))
        _private(directory / f"saml-{revision}.xml", _metadata(issuer, cert, revision))
        if revision != "wrong":
            keys.append(_jwk(key, revision))
    _private(directory / "issuer.json", json.dumps({"issuer": issuer, "jwks": {"keys": keys}}).encode())
    # IAM pins the top intermediate, or the leaf when a leaf/root chain has no intermediate.
    return {"federation_issuer_url": issuer,
            "federation_thumbprint": hashlib.sha1(leaf.public_bytes(serialization.Encoding.DER)).hexdigest()}


@contextlib.contextmanager
def startup(root, endpoint):
    """Own 127.0.0.1:443 for all apply/import/reopen/destroy phases; always close/join.

    The caller sets SSL_CERT_FILE to federation/issuer_ca.pem before launching
    each controller with explicit -oidc-discovery. Binding 443 must be permitted;
    occupied ports fail, never reuse an existing issuer. No DNS or remote fallback.
    """
    local_endpoint(endpoint)
    directory = Path(root) / "federation"
    data = json.loads((directory / "issuer.json").read_text())
    issuer = data["issuer"]
    prefix = urlsplit(issuer).path
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(directory / "issuer_chain.pem", directory / "issuer_key.pem")

    class Server(ThreadingHTTPServer):
        # Permit our closed listener's TIME_WAIT sockets, never a live listener.
        # SO_REUSEPORT is not enabled.
        allow_reuse_address = True
        daemon_threads = False
        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(3)
            try:
                return context.wrap_socket(connection, server_side=True), address
            except Exception:
                connection.close()
                raise

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == prefix + "/.well-known/openid-configuration":
                result = {"issuer": issuer, "jwks_uri": issuer + "/keys",
                          "id_token_signing_alg_values_supported": ["RS256"],
                          "claims_supported": ["iss", "sub", "aud", "iat", "exp"],
                          "response_types_supported": ["id_token"], "subject_types_supported": ["public"]}
            elif self.path == prefix + "/keys":
                result = data["jwks"]
            else:
                self.send_error(404)
                return
            raw = json.dumps(result).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "max-age=0")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        def log_message(self, *_):
            pass

    server = Server(("127.0.0.1", 443), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1},
                              name="owned-federation-issuer")
    started = False
    try:
        thread.start()
        started = True
        trusted = ssl.create_default_context(cafile=str(directory / "issuer_ca.pem"))
        with build_opener(ProxyHandler({}), HTTPSHandler(context=trusted)).open(
                issuer + "/.well-known/openid-configuration", timeout=5) as response:
            require(json.load(response)["issuer"] == issuer, "Owned TLS issuer readiness changed")
        yield
    finally:
        if started:
            server.shutdown()
        server.server_close()
        if started:
            thread.join(timeout=5)
            require(not thread.is_alive(), "Owned federation issuer did not stop")


def _json(endpoint, path):
    with HTTP.open(local_endpoint(endpoint).rstrip("/") + path, timeout=10) as response:
        return json.load(response)


def _clock(endpoint, advance=None):
    request = Request(local_endpoint(endpoint) + "/_stackd/clock",
                      data=None if advance is None else json.dumps({"advance": advance}).encode(),
                      headers={"Content-Type": "application/json"})
    with HTTP.open(request, timeout=10) as response:
        return datetime.fromisoformat(json.load(response)["time"].replace("Z", "+00:00"))


def _reject(call, codes, **kwargs):
    try:
        call(**kwargs)
    except ClientError as error:
        require(error.response["Error"]["Code"] in codes, str(error))
    else:
        raise RuntimeError(f"Invalid federation operation succeeded: {call.__name__}")


def _session(service, endpoint, credentials):
    return boto3.Session(aws_access_key_id=credentials["AccessKeyId"],
                         aws_secret_access_key=credentials["SecretAccessKey"],
                         aws_session_token=credentials["SessionToken"], region_name="us-east-1").client(
        service, endpoint_url=local_endpoint(endpoint), config=Config(
            connect_timeout=3, read_timeout=30, proxies={}, retries={"max_attempts": 0}))


def _jwt(root, revision, issuer, audience, now, signing="v1"):
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": revision}).encode())
    body = _b64url(json.dumps({"iss": issuer, "sub": "local-signed-subject", "aud": audience,
                              "iat": int(now.timestamp()), "exp": int((now + timedelta(hours=1)).timestamp())}).encode())
    message = f"{header}.{body}"
    signature = _key(root, signing).sign(message.encode(), padding.PKCS1v15(), hashes.SHA256())
    return message + "." + _b64url(signature)


def _assertion(root, revision, out, now, signing=None):
    identifier = "_" + uuid.uuid4().hex
    timestamp = lambda value: value.isoformat().replace("+00:00", "Z")
    assertion = etree.Element(f"{{{SAML}}}Assertion", nsmap={"saml": SAML},
                              ID=identifier, Version="2.0", IssueInstant=timestamp(now))
    _child(assertion, SAML, "Issuer", out["issuer_url"])
    subject = _child(assertion, SAML, "Subject")
    _child(subject, SAML, "NameID", "local-signed-subject",
           Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
    confirmation = _child(subject, SAML, "SubjectConfirmation", Method="urn:oasis:names:tc:SAML:2.0:cm:bearer")
    _child(confirmation, SAML, "SubjectConfirmationData", Recipient=RECIPIENT,
           NotOnOrAfter=timestamp(now + timedelta(hours=1)))
    conditions = _child(assertion, SAML, "Conditions", NotBefore=timestamp(now - timedelta(minutes=1)),
                        NotOnOrAfter=timestamp(now + timedelta(hours=1)))
    _child(_child(conditions, SAML, "AudienceRestriction"), SAML, "Audience", "urn:amazon:webservices")
    authentication = _child(assertion, SAML, "AuthnStatement", AuthnInstant=timestamp(now))
    _child(_child(authentication, SAML, "AuthnContext"), SAML, "AuthnContextClassRef",
           "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
    attributes = _child(assertion, SAML, "AttributeStatement")
    for name, value in {"Role": out["saml_role_arn"] + "," + out["saml_arn"],
                        "RoleSessionName": "local-saml-consumer"}.items():
        _child(_child(attributes, SAML, "Attribute", Name="https://aws.amazon.com/SAML/Attributes/" + name),
               SAML, "AttributeValue", value)
    canonical = lambda element: etree.tostring(element, method="c14n", exclusive=True, with_comments=False)
    digest = base64.b64encode(hashlib.sha256(canonical(assertion)).digest()).decode()
    signature = etree.Element(f"{{{DS}}}Signature", nsmap={"ds": DS})
    assertion.insert(1, signature)
    info = _child(signature, DS, "SignedInfo")
    _child(info, DS, "CanonicalizationMethod", Algorithm=C14N)
    _child(info, DS, "SignatureMethod", Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
    reference = _child(info, DS, "Reference", URI="#" + identifier)
    transforms = _child(reference, DS, "Transforms")
    _child(transforms, DS, "Transform", Algorithm=DS + "enveloped-signature")
    _child(transforms, DS, "Transform", Algorithm=C14N)
    _child(reference, DS, "DigestMethod", Algorithm="http://www.w3.org/2001/04/xmlenc#sha256")
    _child(reference, DS, "DigestValue", digest)
    selected = signing or revision
    _child(signature, DS, "SignatureValue", base64.b64encode(
        _key(root, selected).sign(canonical(info), padding.PKCS1v15(), hashes.SHA256())).decode())
    certificate = x509.load_pem_x509_certificate((Path(root) / "federation" / f"signing-{selected}.crt").read_bytes())
    _child(_child(_child(signature, DS, "KeyInfo"), DS, "X509Data"), DS, "X509Certificate",
           base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode())
    response = etree.Element(f"{{{PROTOCOL}}}Response", nsmap={"samlp": PROTOCOL},
                             ID="_" + uuid.uuid4().hex, Version="2.0", IssueInstant=timestamp(now))
    _child(response, SAML, "Issuer", out["issuer_url"])
    _child(_child(response, PROTOCOL, "Status"), PROTOCOL, "StatusCode", Value="urn:oasis:names:tc:SAML:2.0:status:Success")
    response.append(assertion)
    return base64.b64encode(etree.tostring(response)).decode()


def _verify_token(token, jwks, algorithm, issuer, audience, subject, now):
    header, body, signature = token.split(".")
    decoded = json.loads(_decode(header))
    require(decoded["alg"] == algorithm and decoded["typ"] == "JWT", "Outbound header changed")
    keys = [key for key in jwks["keys"] if key["kid"] == decoded["kid"] and key["alg"] == algorithm]
    require(len(keys) == 1, "Outbound token key is absent or ambiguous")
    key = keys[0]
    integer = lambda value: int.from_bytes(_decode(value), "big")
    if algorithm == "RS256":
        public = rsa.RSAPublicNumbers(integer(key["e"]), integer(key["n"])).public_key()
        public.verify(_decode(signature), f"{header}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
    else:
        require(key["crv"] == "P-384", "Outbound curve changed")
        public = ec.EllipticCurvePublicNumbers(integer(key["x"]), integer(key["y"]), ec.SECP384R1()).public_key()
        raw = _decode(signature)
        require(len(raw) == 96, "Invalid ES384 JOSE signature length")
        public.verify(utils.encode_dss_signature(int.from_bytes(raw[:48], "big"), int.from_bytes(raw[48:], "big")),
                      f"{header}.{body}".encode(), ec.ECDSA(hashes.SHA384()))
    claims = json.loads(_decode(body))
    require(claims["iss"] == issuer and claims["sub"] == subject and claims["aud"] == audience,
            "Outbound identity/audience claims changed")
    require(claims["iat"] <= int(now.timestamp()) < claims["exp"] and claims["jti"], "Outbound token lifetime invalid")
    return claims


def verify(endpoint, out, revision, root):
    iam, sts = client("iam", endpoint), client("sts", endpoint)
    directory = Path(root) / "federation"
    now = _clock(endpoint, "10s")  # IAM-to-STS outbound feature propagation is modeled at ten seconds.
    provider = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=out["oidc_arn"])
    require(provider["ClientIDList"] == [out["audience"]], "OIDC audience update was not retained")
    require(provider["Url"] == out["issuer_url"].removeprefix("https://"), "OIDC issuer changed")
    require(len(provider["ThumbprintList"]) == (1 if revision == "v1" else 2), "OIDC thumbprint update was not retained")
    require({tag["Key"]: tag["Value"] for tag in provider["Tags"]}["Revision"] == revision, "OIDC tag update was not retained")
    metadata = iam.get_saml_provider(SAMLProviderArn=out["saml_arn"])
    require(metadata["SAMLMetadataDocument"] == (directory / f"saml-{revision}.xml").read_text(), "SAML signing-certificate update was not retained")
    require({tag["Key"]: tag["Value"] for tag in metadata["Tags"]}["Revision"] == revision, "SAML tag update was not retained")
    oidc_input = {"RoleArn": out["oidc_role_arn"], "RoleSessionName": "local-oidc-consumer", "DurationSeconds": 3600}
    saml_input = {"RoleArn": out["saml_role_arn"], "PrincipalArn": out["saml_arn"], "DurationSeconds": 3600}
    token = _jwt(root, revision, out["issuer_url"], out["audience"], now, signing=revision)
    assertion = _assertion(root, revision, out, now)
    oidc_input["WebIdentityToken"] = token
    saml_input["SAMLAssertion"] = assertion
    credentials = {
        "oidc": sts.assume_role_with_web_identity(**oidc_input)["Credentials"],
        "saml": sts.assume_role_with_saml(**saml_input)["Credentials"],
    }
    for kind, session in credentials.items():
        identity = _session("sts", endpoint, session).get_caller_identity()
        require(identity["Account"] == out["account_id"] and "/" + out[kind + "_role"] + "/" in identity["Arn"], "Federated session identity changed")
        _consume(endpoint, out, revision, session)
    _reject(sts.assume_role_with_web_identity, {"InvalidIdentityToken"}, **{
        **oidc_input, "WebIdentityToken": _jwt(root, revision, out["issuer_url"], out["audience"], now, signing="wrong")})
    _reject(sts.assume_role_with_saml, {"InvalidIdentityToken"}, **{
        **saml_input, "SAMLAssertion": _assertion(root, revision, out, now, signing="wrong")})
    if revision == "v2":
        _reject(sts.assume_role_with_web_identity, {"InvalidIdentityToken"}, **{
            **oidc_input, "WebIdentityToken": _jwt(root, "v1", out["issuer_url"], out["audience"].removesuffix("v2") + "v1", now)})
        _reject(sts.assume_role_with_saml, {"InvalidIdentityToken"}, **{
            **saml_input, "SAMLAssertion": _assertion(root, "v1", out, now)})
    iam.remove_client_id_from_open_id_connect_provider(OpenIDConnectProviderArn=out["oidc_arn"], ClientID=out["audience"])
    try:
        _reject(sts.assume_role_with_web_identity, {"InvalidIdentityToken"}, **oidc_input)
    finally:
        iam.add_client_id_to_open_id_connect_provider(OpenIDConnectProviderArn=out["oidc_arn"], ClientID=out["audience"])
    iam.update_saml_provider(SAMLProviderArn=out["saml_arn"], SAMLMetadataDocument=(directory / "saml-wrong.xml").read_text())
    try:
        _reject(sts.assume_role_with_saml, {"InvalidIdentityToken"}, **saml_input)
    finally:
        iam.update_saml_provider(SAMLProviderArn=out["saml_arn"], SAMLMetadataDocument=(directory / f"saml-{revision}.xml").read_text())
    for kind, request, assume in (("oidc", oidc_input, sts.assume_role_with_web_identity),
                                  ("saml", saml_input, sts.assume_role_with_saml)):
        role = out[kind + "_role"]
        trust = iam.get_role(RoleName=role)["Role"]["AssumeRolePolicyDocument"]
        deny = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Principal": {
            "Federated": out["oidc_arn" if kind == "oidc" else "saml_arn"]},
            "Action": "sts:AssumeRoleWithWebIdentity" if kind == "oidc" else "sts:AssumeRoleWithSAML"}]}
        iam.update_assume_role_policy(RoleName=role, PolicyDocument=json.dumps(deny))
        try:
            _reject(assume, {"AccessDenied"}, **request)
        finally:
            iam.update_assume_role_policy(RoleName=role, PolicyDocument=json.dumps(trust))
        deny_name = "local-current-federation-deny"
        iam.put_role_policy(RoleName=role, PolicyName=deny_name, PolicyDocument=json.dumps({
            "Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "ssm:GetParameter", "Resource": "*"}]}))
        try:
            _reject(_session("ssm", endpoint, credentials[kind]).get_parameter, {"AccessDeniedException"}, Name=out["parameter"])
        finally:
            iam.delete_role_policy(RoleName=role, PolicyName=deny_name)
        _consume(endpoint, out, revision, credentials[kind])
    info = iam.get_outbound_web_identity_federation_info()
    require(info["IssuerIdentifier"] == out["outbound_url"] and info["JwtVendingEnabled"], "Outbound issuer changed")
    issuer = out["outbound_url"]
    require(issuer.startswith(local_endpoint(endpoint) + "/_stackd/oidc/"), "Refusing non-owned outbound issuer")
    discovery_path = urlsplit(issuer).path + "/.well-known/openid-configuration"
    configuration = _json(endpoint, discovery_path)
    require(configuration["issuer"] == issuer and configuration["jwks_uri"] == issuer + "/.well-known/jwks.json", "Outbound discovery leaves owned issuer")
    jwks = _json(endpoint, urlsplit(issuer).path + "/.well-known/jwks.json")
    relying = _session("sts", endpoint, credentials["oidc"])
    deny_name = "local-current-outbound-deny"
    iam.put_role_policy(RoleName=out["oidc_role"], PolicyName=deny_name, PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Deny",
            "Action": "sts:GetWebIdentityToken", "Resource": "*"}]}))
    try:
        _reject(relying.get_web_identity_token, {"AccessDenied"},
                Audience=[out["audience"]], DurationSeconds=300, SigningAlgorithm="RS256")
    finally:
        iam.delete_role_policy(RoleName=out["oidc_role"], PolicyName=deny_name)
    for algorithm in ("RS256", "ES384"):
        outbound = relying.get_web_identity_token(Audience=[out["audience"]], DurationSeconds=300,
                    SigningAlgorithm=algorithm, Tags=[{"Key": "Revision", "Value": revision}])["WebIdentityToken"]
        claims = _verify_token(outbound, jwks, algorithm, issuer, out["audience"], out["oidc_role_arn"], _clock(endpoint))
        custom = claims["https://sts.amazonaws.com/"]
        require(custom["aws_account"] == out["account_id"] and custom["request_tags"] == {"Revision": revision}, "Outbound signed caller context changed")
        header, body, signature = outbound.split(".")
        raw = _decode(signature)
        corrupted = header + "." + body + "." + _b64url(raw[:-1] + bytes([raw[-1] ^ 1]))
        try:
            _verify_token(corrupted, jwks, algorithm, issuer, out["audience"], out["oidc_role_arn"], _clock(endpoint))
        except InvalidSignature:
            pass
        else:
            raise RuntimeError("Outbound relying party accepted a wrong signature")
        _reject(sts.assume_role_with_web_identity, {"InvalidIdentityToken"}, **{**oidc_input, "WebIdentityToken": outbound})
    iam.disable_outbound_web_identity_federation()
    try:
        _clock(endpoint, "10s")
        _reject(relying.get_web_identity_token, {"OutboundWebIdentityFederationDisabledException"},
                Audience=[out["audience"]], DurationSeconds=300, SigningAlgorithm="RS256")
    finally:
        iam.enable_outbound_web_identity_federation()
        _clock(endpoint, "10s")
    reopened = relying.get_web_identity_token(Audience=[out["audience"]], DurationSeconds=300, SigningAlgorithm="RS256")["WebIdentityToken"]
    _verify_token(reopened, jwks, "RS256", issuer, out["audience"], out["oidc_role_arn"], _clock(endpoint))
    checkpoint = directory / "consumer-checkpoint.json"
    if checkpoint.exists():
        previous = json.loads(checkpoint.read_text())
        require(previous["issuer"] == issuer and previous["jwks"] == jwks, "SQLite reopen/import changed outbound signing authority")
        for session in previous["sessions"].values():
            _consume(endpoint, out, revision, session)
        checkpoint.unlink()
    _private(checkpoint, json.dumps({"issuer": issuer, "jwks": jwks, "token": reopened,
        "audience": out["audience"], "subject": out["oidc_role_arn"], "sessions": {
        kind: {key: value for key, value in session.items() if key != "Expiration"}
        for kind, session in credentials.items()}}).encode())


def _consume(endpoint, out, revision, session):
    result = _session("ssm", endpoint, session).get_parameter(Name=out["parameter"])["Parameter"]
    require(result["Value"] == "signed-federation-consumer-" + revision, "Signed federation session did not consume actual current SSM bytes")


def verify_deleted(endpoint, out, root):
    iam = client("iam", endpoint)
    expect_missing(iam.get_open_id_connect_provider, {"NoSuchEntity"}, OpenIDConnectProviderArn=out["oidc_arn"])
    expect_missing(iam.get_saml_provider, {"NoSuchEntity"}, SAMLProviderArn=out["saml_arn"])
    expect_missing(iam.get_outbound_web_identity_federation_info, {"FeatureDisabled"})
    expect_missing(client("ssm", endpoint).get_parameter, {"ParameterNotFound"}, Name=out["parameter"])
    for role in (out["oidc_role"], out["saml_role"]):
        expect_missing(iam.get_role, {"NoSuchEntity"}, RoleName=role)
    require(out["oidc_arn"] not in {value["Arn"] for value in iam.list_open_id_connect_providers()["OpenIDConnectProviderList"]}, "Deleted OIDC provider remains listed")
    require(out["saml_arn"] not in {value["Arn"] for value in iam.list_saml_providers()["SAMLProviderList"]}, "Deleted SAML provider remains listed")
    now = _clock(endpoint, "10s")
    _reject(client("sts", endpoint).assume_role_with_web_identity, {"InvalidIdentityToken"},
            RoleArn=out["oidc_role_arn"], RoleSessionName="deleted-provider",
            WebIdentityToken=_jwt(root, "v2", out["issuer_url"], out["audience"], now, signing="v2"))
    _reject(client("sts", endpoint).assume_role_with_saml, {"InvalidIdentityToken"},
            RoleArn=out["saml_role_arn"], PrincipalArn=out["saml_arn"], SAMLAssertion=_assertion(root, "v2", out, now))
    # Disable is the Terraform deletion contract, not signing-key destruction.
    # Retained public keys allow a relying party to authenticate already-issued
    # unexpired tokens; they confer no authority to vend another token.
    previous = json.loads((Path(root) / "federation" / "consumer-checkpoint.json").read_text())
    jwks = _json(endpoint, urlsplit(out["outbound_url"]).path + "/.well-known/jwks.json")
    require(jwks == previous["jwks"], "Outbound teardown unexpectedly changed retained signing keys")
    claims = json.loads(_decode(previous["token"].split(".")[1]))
    if now.timestamp() < claims["exp"]:
        _verify_token(previous["token"], jwks, "RS256", out["outbound_url"],
                      previous["audience"], previous["subject"], now)


def imports(resources):
    """Native IDs for this slice only, from terraform show's root resources."""
    selectors = {
        "aws_iam_openid_connect_provider.federation": lambda value: value["arn"],
        "aws_iam_saml_provider.federation": lambda value: value["arn"],
        "aws_iam_outbound_web_identity_federation.federation":
            lambda value: urlsplit(value["issuer_identifier"]).path.split("/")[4],
        "aws_iam_role.federation_oidc": lambda value: value["name"],
        "aws_iam_role.federation_saml": lambda value: value["name"],
        "aws_iam_role_policy.federation_oidc": lambda value: value["role"] + ":" + value["name"],
        "aws_iam_role_policy.federation_saml": lambda value: value["role"] + ":" + value["name"],
        "aws_ssm_parameter.federation": lambda value: value["name"],
    }
    return {resource["address"]: selectors[resource["address"]](resource["values"])
            for resource in resources if resource["address"] in selectors}
