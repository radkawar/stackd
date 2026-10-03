#!/usr/bin/env python3
"""Capture signed OIDC JWT behavior using two public S3 objects and owned IAM resources.

Real AWS only; all created resources are removed in finally. No account settings
are modified. Returned AWS credentials are never printed or written to captures.
"""
import argparse
import base64
import datetime
import json
from pathlib import Path
import subprocess
import copy
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
CAPTURE_DIR = ROOT / ".stackd/probes/sts/oidc"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--account", required=True, help="AWS account ID authorized for this probe")
parser.add_argument("--authorized-roles", action="store_true", help="capture authorized-role JWT claims")
parser.add_argument("--trust-context", action="store_true", help="capture OIDC trust policy context")
parser.add_argument("--key-semantics", action="store_true", help="capture JWK selection and certificate behavior")
args = parser.parse_args()
PREFIX = "stackd-oidc-probe-" + uuid.uuid4().hex[:12]
REGION = "us-east-1"
ISSUER = "https://" + PREFIX + ".s3.us-east-1.amazonaws.com"
ROWS = []
CREATED = {"bucket": False, "provider": None, "role": False}
EXTRA_ROLES = []


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def aws(service, action, parameters=None, options=None, unsigned=False):
    args = ["aws", service, action, "--region", REGION, "--output", "json", "--no-cli-pager"]
    endpoints = {"iam": "https://iam.amazonaws.com", "sts": "https://sts.us-east-1.amazonaws.com", "s3api": "https://s3.us-east-1.amazonaws.com"}
    args += ["--endpoint-url", endpoints[service]]
    if parameters is not None:
        args += ["--cli-input-json", json.dumps(parameters)]
    args += options or []
    if unsigned:
        args += ["--no-sign-request"]
    result = subprocess.run(args, capture_output=True, text=True, timeout=60)
    output = json.loads(result.stdout) if result.returncode == 0 and result.stdout.strip() else {}
    return result.returncode, output, result.stderr


def require(service, action, parameters=None, options=None):
    code, output, error = aws(service, action, parameters, options)
    if code:
        raise RuntimeError(service + " " + action + ": " + error)
    return output


def der_length(data, offset):
    length = data[offset]
    offset += 1
    if length & 128:
        count = length & 127
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    return length, offset


def signature(algorithm, path, message):
    result = subprocess.run(["openssl", "dgst", "-sha" + algorithm[2:], "-sign", str(path)], input=message, capture_output=True, check=True).stdout
    if algorithm.startswith("ES"):
        _, offset = der_length(result, 1)
        coordinates = []
        for _ in range(2):
            assert result[offset] == 2
            length, offset = der_length(result, offset + 1)
            coordinates.append(int.from_bytes(result[offset:offset + length], "big"))
            offset += length
        size = {"ES256": 32, "ES384": 48, "ES512": 66}[algorithm]
        result = b"".join(value.to_bytes(size, "big") for value in coordinates)
    return result


def token(algorithm, claims, header=None, claim_text=None):
    header = header if header is not None else {"alg": algorithm, "kid": algorithm, "typ": "JWT"}
    raw_header = header if isinstance(header, str) else json.dumps(header, separators=(",", ":"))
    raw_claims = claim_text if claim_text is not None else json.dumps(claims, separators=(",", ":"))
    unsigned = b64(raw_header.encode()) + "." + b64(raw_claims.encode())
    return unsigned + "." + b64(signature(algorithm, KEYS[algorithm], unsigned.encode()))


def observe(name, claims, algorithm="RS256", header=None, token_value=None, extra=None, claim_text=None):
    value = token_value or token(algorithm, claims, header, claim_text)
    parameters = {"RoleArn": ROLE_ARN, "RoleSessionName": "oidc-probe", "WebIdentityToken": value, **(extra or {})}
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    code, output, error = aws("sts", "assume-role-with-web-identity", parameters, unsigned=True)
    credentials = output.pop("Credentials", None)
    if credentials:
        output["CredentialExpiration"] = credentials["Expiration"]
        output["CredentialAccessKeyPrefix"] = credentials["AccessKeyId"][:4]
    ROWS.append({"scenario": name, "input": parameters, "algorithm": algorithm, "claims": claims,
                 "output": output, "exit_code": code, "error": error, "observed_at": started, "jwks": {"keys": public_keys}})
    print(name, code, error.strip() if code else "verified", flush=True)
    return code


account = require("sts", "get-caller-identity")["Account"]
if account != args.account:
    raise RuntimeError("Unexpected native AWS account")
CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

KEYS = {}
try:
    rsa_path = CAPTURE_DIR / "rsa2048.pem"
    if not rsa_path.exists():
        rsa_path.write_bytes(subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"], capture_output=True, check=True).stdout)
    modulus = subprocess.run(["openssl", "rsa", "-in", str(rsa_path), "-noout", "-modulus"], capture_output=True, check=True).stdout.decode().strip().split("=")[1]
    public_keys = []
    for algorithm in ["RS256", "RS384", "RS512"]:
        KEYS[algorithm] = rsa_path
        public_keys.append({"kid": algorithm, "kty": "RSA", "alg": algorithm, "use": "sig", "n": b64(bytes.fromhex(modulus)), "e": "AQAB"})
    for algorithm, curve, size, jwk_curve in [("ES256", "prime256v1", 32, "P-256"), ("ES384", "secp384r1", 48, "P-384"), ("ES512", "secp521r1", 66, "P-521")]:
        path = CAPTURE_DIR / (algorithm.lower() + ".pem")
        if not path.exists():
            path.write_bytes(subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:" + curve], capture_output=True, check=True).stdout)
        public_der = subprocess.run(["openssl", "pkey", "-in", str(path), "-pubout", "-outform", "DER"], capture_output=True, check=True).stdout
        point = public_der[-(size * 2 + 1):]
        assert point[0] == 4
        KEYS[algorithm] = path
        public_keys.append({"kid": algorithm, "kty": "EC", "alg": algorithm, "use": "sig", "crv": jwk_curve, "x": b64(point[1:1 + size]), "y": b64(point[1 + size:])})
    metadata = {"issuer": ISSUER, "jwks_uri": ISSUER + "/keys.json", "id_token_signing_alg_values_supported": list(KEYS), "response_types_supported": ["id_token"], "subject_types_supported": ["public"], "claims_supported": ["iss", "sub", "aud", "iat", "exp"]}
    (CAPTURE_DIR / "jwks.json").write_text(json.dumps({"keys": public_keys}, indent=2) + "\n")
    require("s3api", "create-bucket", {"Bucket": PREFIX})
    CREATED["bucket"] = True
    require("s3api", "put-public-access-block", {"Bucket": PREFIX, "PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": False, "RestrictPublicBuckets": False}})
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": ["arn:aws:s3:::" + PREFIX + "/.well-known/openid-configuration", "arn:aws:s3:::" + PREFIX + "/keys.json"]}]}
    require("s3api", "put-bucket-policy", {"Bucket": PREFIX, "Policy": json.dumps(policy)})
    with tempfile.TemporaryDirectory() as directory:
        for key, document in [(".well-known/openid-configuration", metadata), ("keys.json", {"keys": public_keys})]:
            path = Path(directory) / "document.json"
            path.write_text(json.dumps(document))
            require("s3api", "put-object", options=["--bucket", PREFIX, "--key", key, "--body", str(path), "--content-type", "application/json", "--cache-control", "no-cache"])
    provider = require("iam", "create-open-id-connect-provider", {"Url": ISSUER, "ClientIDList": ["client-a", "client-b"]})
    CREATED["provider"] = provider["OpenIDConnectProviderArn"]
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Federated": CREATED["provider"]}, "Action": ["sts:AssumeRoleWithWebIdentity", "sts:TagSession", "sts:SetSourceIdentity"]}]}
    role = require("iam", "create-role", {"RoleName": PREFIX, "AssumeRolePolicyDocument": json.dumps(trust), "MaxSessionDuration": 7200})
    CREATED["role"] = True
    ROLE_ARN = role["Role"]["Arn"]
    now = int(time.time())
    base = {"iss": ISSUER, "aud": "client-a", "sub": "subject-probe", "iat": now - 10, "exp": now + 900}
    for attempt in range(5):
        if observe("baseline-" + str(attempt), base) == 0:
            break
        time.sleep(3)
    if args.authorized_roles:
        claim = "https://aws.amazon.com/roles"
        other = "arn:aws:iam::"+account+":role/another-role"
        variants = [
            ("roles-array-match", [ROLE_ARN]), ("roles-string-match", ROLE_ARN),
            ("roles-array-many", [other, ROLE_ARN]), ("roles-semicolon-many", other+";"+ROLE_ARN),
            ("roles-mismatch", [other]), ("roles-array-empty", []), ("roles-string-empty", ""),
            ("roles-null", None), ("roles-number", 123), ("roles-bool", True), ("roles-object", {"role":ROLE_ARN}),
            ("roles-mixed-array", [123, ROLE_ARN]), ("roles-nested-array", [[ROLE_ARN]]),
            ("roles-surrounding-space", " "+ROLE_ARN+" "), ("roles-semicolon-space", other+"; "+ROLE_ARN),
            ("roles-wildcard", "arn:aws:iam::"+account+":role/*"), ("roles-case", ROLE_ARN.upper()),
            ("roles-duplicate", [ROLE_ARN, ROLE_ARN]), ("roles-invalid-other", ["not-an-arn", ROLE_ARN]),
            ("roles-trailing-separator", ROLE_ARN+";"), ("roles-empty-first", ";"+ROLE_ARN),
            ("roles-comma-list", other+","+ROLE_ARN), ("roles-array-null", [None, ROLE_ARN]),
        ]
        for name, value in variants:
            observe(name, {**base, claim:value})
            ROWS[-1]["trust_policy"] = trust
        for expected in [True, False]:
            name = PREFIX + ("-idptrue" if expected else "-idpfalse")
            document = {"Version":"2012-10-17", "Statement":[
                {"Effect":"Allow", "Principal":{"Federated":CREATED["provider"]}, "Action":"sts:AssumeRoleWithWebIdentity", "Condition":{"StringEquals":{"sts:RoleSessionName":"propagation-control"}}},
                {"Effect":"Allow", "Principal":{"Federated":CREATED["provider"]}, "Action":"sts:AssumeRoleWithWebIdentity", "Condition":{"Bool":{"sts:RoleAuthorizedByIdp":str(expected).lower()}}},
            ]}
            result = require("iam", "create-role", {"RoleName":name,"AssumeRolePolicyDocument":json.dumps(document)})
            EXTRA_ROLES.append(name)
            role_arn = result["Role"]["Arn"]
            for attempt in range(8):
                code = observe("roles-bool-"+str(expected).lower()+"-control-"+str(attempt), base, extra={"RoleArn":role_arn,"RoleSessionName":"propagation-control"})
                ROWS[-1]["trust_policy"] = document
                ROWS[-1]["control"] = True
                if code == 0:
                    break
                time.sleep(3)
            if code != 0:
                raise RuntimeError("Role propagation control failed: " + name)
            for suffix, claims in [("absent", base), ("matching", {**base,claim:[role_arn]}), ("mismatch",{**base,claim:[other]})]:
                observe("roles-bool-"+str(expected).lower()+"-"+suffix, claims, extra={"RoleArn":role_arn})
                ROWS[-1]["trust_policy"] = document
        raise SystemExit(0)
    if args.trust_context:
        # Independent role policies avoid eventual-consistency ambiguity from
        # repeated trust updates. Each role has an explicit-Federated control
        # statement gated by a different session name to prove propagation.
        probes = [
            ("principal-account-role", {"StringEquals": {"aws:PrincipalAccount": account}}, None),
            ("principal-account-anonymous", {"StringEquals": {"aws:PrincipalAccount": "anonymous"}}, None),
            ("principal-type-user", {"StringEquals": {"aws:PrincipalType": "User"}}, None),
            ("principal-type-federated-user", {"StringEquals": {"aws:PrincipalType": "FederatedUser"}}, None),
            ("principal-type-assumed-role", {"StringEquals": {"aws:PrincipalType": "AssumedRole"}}, None),
            ("userid-provider", {"StringEquals": {"aws:userid": CREATED["provider"]}}, None),
            ("userid-subject", {"StringEquals": {"aws:userid": base["sub"]}}, None),
            ("userid-provider-colon-subject", {"StringEquals": {"aws:userid": CREATED["provider"]+":"+base["sub"]}}, None),
            ("principal-arn-absent", {"Null": {"aws:PrincipalArn": "true"}}, None),
            ("principal-arn-provider", {"StringEquals": {"aws:PrincipalArn": CREATED["provider"]}}, None),
            ("aws-wildcard-principal", None, {"AWS": "*"}),
        ]
        roles = []
        for index, (name, condition, principal) in enumerate(probes):
            role_name = PREFIX + "-" + str(index)
            statements = [
                {"Effect": "Allow", "Principal": {"Federated": CREATED["provider"]}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"sts:RoleSessionName": "propagation-control"}}},
                {"Effect": "Allow", "Principal": principal or {"Federated": CREATED["provider"]}, "Action": "sts:AssumeRoleWithWebIdentity"},
            ]
            if condition:
                statements[1]["Condition"] = condition
            document = {"Version": "2012-10-17", "Statement": statements}
            created = require("iam", "create-role", {"RoleName": role_name, "AssumeRolePolicyDocument": json.dumps(document)})
            EXTRA_ROLES.append(role_name)
            roles.append((name, created["Role"]["Arn"], document))
        for name, role_arn, document in roles:
            for attempt in range(8):
                code = observe(name+"-control-"+str(attempt), base, extra={"RoleArn": role_arn, "RoleSessionName": "propagation-control"})
                ROWS[-1]["trust_policy"] = document
                ROWS[-1]["control"] = True
                if code == 0:
                    break
                time.sleep(3)
            if code != 0:
                raise RuntimeError("Role propagation control failed: " + name)
            observe(name, base, extra={"RoleArn": role_arn})
            ROWS[-1]["trust_policy"] = document
        # ProviderId validation needs no additional infrastructure. These calls
        # use the already owned, propagated role and exact signed JWT.
        for provider_id in ["www.amazon.com", "graph.facebook.com", "accounts.google.com", "https://www.amazon.com", "custom.example.test"]:
            observe("provider-id-"+provider_id, base, extra={"ProviderId": provider_id})
        raise SystemExit(0)
    if args.key_semantics:
        rsa_jwk = copy.deepcopy(public_keys[0])
        ec_jwk = copy.deepcopy(public_keys[3])
        cert_pem = subprocess.run(["openssl", "req", "-new", "-x509", "-key", str(rsa_path), "-subj", "/CN=stackd-jwt-test", "-days", "1"], capture_output=True, check=True).stdout
        (CAPTURE_DIR / "rsa-certificate.pem").write_bytes(cert_pem)
        certificate = "".join(cert_pem.decode().splitlines()[1:-1])
        variants = [
            ("key-single", [rsa_jwk], "RS256", None),
            ("key-no-header-kid", [rsa_jwk], "RS256", {"alg":"RS256"}),
            ("key-no-jwk-kid", [{k:v for k,v in rsa_jwk.items() if k != "kid"}], "RS256", {"alg":"RS256"}),
            ("key-wrong-alg", [{**rsa_jwk,"alg":"RS512"}], "RS256", None),
            ("key-encryption-use", [{**rsa_jwk,"use":"enc"}], "RS256", None),
            ("key-ops-sign", [{**rsa_jwk,"key_ops":["sign"]}], "RS256", None),
            ("key-ops-verify", [{**rsa_jwk,"key_ops":["verify"]}], "RS256", None),
            ("key-duplicate-identical", [rsa_jwk,rsa_jwk], "RS256", None),
            ("key-duplicate-wrong-first", [{**rsa_jwk,"n":rsa_jwk["n"][:-4]+"AAAA"},rsa_jwk], "RS256", None),
            ("key-duplicate-wrong-last", [rsa_jwk,{**rsa_jwk,"n":rsa_jwk["n"][:-4]+"AAAA"}], "RS256", None),
            ("key-x5c-matching", [{**rsa_jwk,"x5c":[certificate]}], "RS256", None),
            ("key-x5c-only", [{"kty":"RSA","kid":"RS256","x5c":[certificate]}], "RS256", None),
            ("key-x5c-conflict", [{**rsa_jwk,"n":rsa_jwk["n"][:-4]+"AAAA","x5c":[certificate]}], "RS256", None),
            ("key-rsa-101", [rsa_jwk]+[{**rsa_jwk,"kid":"extra"+str(i)} for i in range(100)]+[ec_jwk], "RS256", None),
            ("key-rsa-101-ec-token", [rsa_jwk]+[{**rsa_jwk,"kid":"extra"+str(i)} for i in range(100)]+[ec_jwk], "ES256", None),
        ]
        for name, selection, algorithm, header in variants:
            public_keys = selection
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "jwks.json"
                path.write_text(json.dumps({"keys": public_keys}))
                require("s3api", "put-object", options=["--bucket", PREFIX, "--key", "keys.json", "--body", str(path), "--content-type", "application/json", "--cache-control", "no-cache"])
            observe(name, base, algorithm=algorithm, header=header)
        raise SystemExit(0)
    for algorithm in KEYS:
        observe("algorithm-" + algorithm, base, algorithm)
    for claim in ["iss", "sub", "aud", "iat", "exp"]:
        claims = dict(base)
        claims.pop(claim)
        observe("missing-" + claim, claims)
    for name, patch in [
        ("subject-short", {"sub": "a"}), ("subject-empty", {"sub": ""}),
        ("aud-array-first-match", {"aud": ["client-a", "other"]}), ("aud-array-second-match", {"aud": ["other", "client-a"]}),
        ("aud-array-two-matches", {"aud": ["client-b", "client-a"]}), ("azp-overrides", {"aud": "other", "azp": "client-b"}),
        ("azp-mismatch", {"azp": "other"}), ("azp-empty", {"azp": ""}),
        ("expired-1", {"exp": now - 1}), ("expired-301", {"exp": now - 301}),
        ("iat-future-1", {"iat": now + 1}), ("iat-future-301", {"iat": now + 301}),
        ("nbf-future-1", {"nbf": now + 1}), ("nbf-future-301", {"nbf": now + 301}),
        ("iat-future-hour", {"iat": now + 3600}), ("nbf-future-hour", {"nbf": now + 3600}),
        ("nbf-string", {"nbf": str(now)}), ("nbf-invalid", {"nbf": "invalid"}),
        ("aud-empty", {"aud": ""}), ("aud-single-array", {"aud": ["client-a"]}),
        ("aud-multi-with-azp", {"aud": ["other", "client-a"], "azp": "client-b"}),
        ("aud-empty-array", {"aud": []}), ("sub-null", {"sub": None}), ("sub-number", {"sub": 123}), ("sub-long", {"sub": "a" * 300}),
        ("exp-string", {"exp": str(now + 600)}), ("iat-null", {"iat": None}),
        ("iat-fraction", {"iat": now - 0.5}), ("exp-fraction", {"exp": now + 100.5}), ("iat-string", {"iat": str(now)}),
        ("source-identity", {"https://aws.amazon.com/source_identity": "source-probe"}),
        ("nested-tags", {"https://aws.amazon.com/tags": {"principal_tags": {"Team": ["engineering"]}, "transitive_tag_keys": ["Team"]}}),
        ("nested-string-tags", {"https://aws.amazon.com/tags": {"principal_tags": {"Team": "engineering"}}}),
        ("flat-tags", {"https://aws.amazon.com/tags/principal_tags/Team": "engineering", "https://aws.amazon.com/tags/transitive_tag_keys": ["Team"]}),
    ]:
        observe(name, {**base, **patch})
    observe("token-expiry-does-not-cap-session", {**base, "exp": int(time.time()) + 60}, extra={"DurationSeconds": 7200})
    observe("provider-id-with-oidc", base, extra={"ProviderId": "www.amazon.com"})
    observe("unknown-key-id", base, header={"alg": "RS256", "kid": "unknown"})
    observe("missing-key-id", base, header={"alg": "RS256"})
    observe("empty-key-id", base, header={"alg": "RS256", "kid": ""})
    observe("critical-header", base, header={"alg": "RS256", "kid": "RS256", "crit": ["custom"], "custom": "yes"})
    observe("duplicate-claim", base, claim_text=json.dumps(base)[:-1] + ', "aud":"other"}')
    observe("duplicate-same-claim", base, claim_text=json.dumps(base)[:-1] + ', "aud":"client-a"}')
finally:
    failures = []
    for role_name in reversed(EXTRA_ROLES):
        code, _, error = aws("iam", "delete-role", {"RoleName": role_name})
        if code:
            failures.append({"service": "iam", "action": "delete-role", "input": {"RoleName": role_name}, "error": error})
    for active, service, action, parameters in [
        (CREATED["role"], "iam", "delete-role", {"RoleName": PREFIX}),
        (CREATED["provider"], "iam", "delete-open-id-connect-provider", {"OpenIDConnectProviderArn": CREATED["provider"]}),
        (CREATED["bucket"], "s3api", "delete-object", {"Bucket": PREFIX, "Key": ".well-known/openid-configuration"}),
        (CREATED["bucket"], "s3api", "delete-object", {"Bucket": PREFIX, "Key": "keys.json"}),
        (CREATED["bucket"], "s3api", "delete-bucket", {"Bucket": PREFIX}),
    ]:
        if active:
            code, _, error = aws(service, action, parameters)
            if code:
                failures.append({"service": service, "action": action, "input": parameters, "error": error})
    # Confirm absence after deletion rather than relying on successful delete
    # responses alone. None of these reads can touch another run's resources.
    checks = [("iam", "get-role", {"RoleName": name}, "NoSuchEntity") for name in EXTRA_ROLES]
    if CREATED["role"]:
        checks.append(("iam", "get-role", {"RoleName": PREFIX}, "NoSuchEntity"))
    if CREATED["provider"]:
        checks.append(("iam", "get-open-id-connect-provider", {"OpenIDConnectProviderArn": CREATED["provider"]}, "NoSuchEntity"))
    if CREATED["bucket"]:
        checks.append(("s3api", "get-bucket-location", {"Bucket": PREFIX}, "NoSuchBucket"))
    for service, action, parameters, expected in checks:
        code, _, error = aws(service, action, parameters)
        if code == 0 or expected not in error:
            failures.append({"service": service, "action": action, "input": parameters, "error": error or "Owned resource still exists"})
    fixture = {"source": "Real AWS STS with cryptographically signed synthetic JWTs, uniquely owned two-object S3 issuer and IAM provider/role", "endpoint": "https://sts.us-east-1.amazonaws.com", "region": REGION, "issuer": ISSUER, "probe": "scripts/aws/sts_oidc_probe.py", "cleanup_complete": not failures, "cleanup_verified": not failures, "cleanup_failures": failures, "scenarios": ROWS}
    # Keep exact JWT bytes, embedded role claims and cleanup resource identities
    # together in the ignored raw capture; these are not publication fixtures.
    fixture["source_account_id"] = account
    filename = "aws-roles.json" if args.authorized_roles else ("aws-trust.json" if args.trust_context else ("aws-keys.json" if args.key_semantics else "aws.json"))
    (CAPTURE_DIR / filename).write_text(json.dumps(fixture, indent=2) + "\n")
    if failures:
        raise RuntimeError("Owned probe resource cleanup failed; see capture cleanup_failures")
