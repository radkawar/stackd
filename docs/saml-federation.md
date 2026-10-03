# SAML federation verification

`AssumeRoleWithSAML` uses generated SDK request/response bindings and the verifier
in `internal/services/sts/saml_*.go`. Signed and encrypted assertions are checked
against a detached IAM provider snapshot, then the shared federation authority
evaluates current role trust and issues credentials atomically. The gateway
accepts this operation without AWS signing credentials. SDK tests exercise the
HTTP handler, modeled errors, claims, session lifetimes and trust denials;
cryptographic verification alone is not treated as proof of API compatibility.

## Trust and parsing

The selected IAM provider owns issuer-specific signing certificates and up to two
decryption keys. An assertion's issuer selects the corresponding pinned
certificate set; verification must succeed before any claim is authoritative.
An embedded `KeyInfo` certificate supplies no independent trust. Certificates for
another issuer in the same metadata document cannot authenticate the assertion.

The XML reader rejects directives, external entities, extra roots, duplicate
attributes and IDs, excessive depth, ambiguous assertions and hidden signatures.
Round-trip validation runs before namespace-aware subtree selection. A signature
must be directly attached to its target, with one local reference to that
target's ID and supported enveloped/canonicalization transforms. Assertion
namespaces inherited from the response are preserved when detaching the subtree.
Only the verified subtree supplies claims. Both signatures must verify when a
response and its assertion are signed; a response signature does not replace the
mandatory assertion signature.

XML signatures use `goxmldsig` v1.6.1, `etree` v1.8.0 and
`xml-roundtrip-validator` v0.1.0. XML Encryption uses Go's standard `crypto/rsa`,
`crypto/aes` and `crypto/cipher`: RSA OAEP supports separate digest and MGF1 hash
declarations, and AES supports 128/256-bit CBC/GCM. Ciphertext lengths, key lengths,
GCM nonce/tag sizes and XML Encryption CBC padding are checked before use.
Provider keys are tried newest first. Decryption is followed by mandatory
assertion signature verification; successful decryption alone grants no trust.
Ciphertext and signature failures produce generic token errors and do not reveal
private material.

An inspected alternative, `crewjam/saml` v0.5.1's XML Encryption package, did not
provide the needed AES-256/GCM and separate OAEP/MGF behavior, and its short-buffer
handling would need additional protection. Rather than depend on that broader
SAML service-provider implementation, this boundary uses maintained XML signature
and canonicalization code together with explicit XML Encryption schema checks
and standard cryptographic primitives. See the
[signature validator](https://github.com/russellhaering/goxmldsig/blob/v1.6.1/validate.go),
[round-trip validator](https://github.com/mattermost/xml-roundtrip-validator/blob/v0.1.0/validator.go),
and inspected [XML Encryption implementation](https://github.com/crewjam/saml/tree/v0.5.1/xmlenc).

## Observed STS behavior

`internal/services/sts/testdata/saml_aws.json` records 45 signed-assertion scenarios
against real AWS STS in `us-east-1` on 2026-09-11. A separate
`saml_required_aws.json` captures four cases against a provider created with
encryption required. Both fixtures record successful deletion and absence checks
for every probe-owned role and provider. The role has a federation trust policy
and no attached permission policies. Returned credentials are neither persisted
nor logged. The probe deliberately uses an expired signing certificate.

| Behavior | AWS observation |
| --- | --- |
| Assertion signature | Mandatory, even when the response is signed. |
| Response signature | Optional, but invalid signatures are rejected. |
| Issuer | Assertion issuer is authoritative; an unsigned response issuer may differ. |
| Signing certificate expiry | Does not prevent authentication with the pinned signing key. |
| `Recipient` | Required, returned as `Audience`, and projected to `saml:aud`. Arbitrary strings succeed when the role trust policy allows them. |
| `AudienceRestriction` | Wrong or absent audiences do not reject this API call; role trust conditions enforce the intended recipient. |
| `NotBefore` | Must parse as a timestamp if present; a value a day in the future is accepted. |
| `OneTimeUse` | Reusing the exact signed assertion still succeeds; the fixture records the repeated call. |
| `NotOnOrAfter` | Subject confirmation expiry is required; conditions expiry is optional. Expired assertion/session timestamps return `ExpiredTokenException`. |
| NameID format | Required. The SAML 2.0 format prefix is stripped in `SubjectType`; other values are preserved. |
| `SessionDuration` attribute | Can shorten the API duration; cannot extend it. |
| `SessionNotOnOrAfter` | Caps issued credential lifetime, including a remaining lifetime shorter than 900 seconds. |
| Encrypted assertions | AES-128/256 CBC/GCM and RSA OAEP with SHA-256/MGF1-SHA1 or SHA-256/MGF1-SHA256 succeed. |
| Required encryption | Rejects plaintext. An encrypted assertion's recipient need not contain the provider UUID, and a differing UUID does not independently reject the STS call. |

These observations concern the direct STS API, not browser console sign-in.
They explain why generic SAML service-provider audience/recipient validation
would differ from AWS. The original documentation remains useful for deployment
guidance and API contracts:

- [AssumeRoleWithSAML API](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithSAML.html)
- [AWS assertion attributes and context mapping](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml_assertions.html)
- [Provider keys, encryption and certificate validity](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml.html)
- [SAML condition keys and session availability](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html)

The additional `saml_trust_aws.json` and `saml_userid_aws.json` fixtures probe
static role trust policies and provider recreation. During the unsigned SAML
assumption, `aws:PrincipalAccount` is the provider/role account,
`aws:PrincipalType` is `User`, `aws:userid` is the provider ARN, and
`aws:PrincipalArn` is absent. These are assumption-time values, distinct from
the resulting assumed-role session's context. An explicit `Federated` provider
principal permits assumption; an `AWS: "*"` principal does not. A scalar
`Principal: "*"` is rejected by IAM for both SAML and ordinary role trust policies.

Deleting and recreating a provider at the same ARN preserves the existing role
trust. Its replacement signing key succeeds and the previous key fails. Thus
persisted role trust uses provider ARNs; immutable provider IDs and configuration
versions fence concurrent changes during verification and issuance, rather than
permanently binding a role to the original provider incarnation.

## Integration contract

`SAMLProviderSource.SAMLProviderForFederation(ctx, arn)` returns a detached
`SAMLProviderSnapshot`, including its immutable incarnation ID and configuration
version. The verified claims supply the requested role/session identity,
principal tags, transitive tag keys, source identity and trust context. Only
`saml:sub`, `saml:sub_type` and `saml:namequalifier` persist as downstream session
context; the remaining SAML keys apply at assumption time.

The common issuer must evaluate the role trust policy and the additional
`sts:TagSession` / `sts:SetSourceIdentity` permissions where applicable. It must
recheck the current provider incarnation/version and role ID inside the final
credential transaction. Requested duration is checked against the role maximum
before applying assertion lifetime caps. Session policies intersect the role's
current policies, with managed policy ARN references resolved dynamically.

## Reproducing the evidence

Offline verification needs no clone, network or AWS credentials:

```sh
go test ./internal/services/sts -run '^TestSAML' -count=1
```

The following commands explicitly authorize creation of a temporary provider
and assertion or trust-test roles in the configured AWS account. They require normal AWS SDK
credentials with the corresponding IAM permissions and capture fixtures only
after cleanup is verified:

```sh
STACKD_SAML_AWS_PROBE_WRITE=1 go test ./internal/services/sts -run '^TestSAMLProbeAWS$' -count=1 -v
STACKD_SAML_AWS_PROBE_WRITE=1 STACKD_SAML_AWS_PROBE_REQUIRED=1 go test ./internal/services/sts -run '^TestSAMLProbeAWS$' -count=1 -v
STACKD_SAML_AWS_TRUST_PROBE_WRITE=1 go test ./internal/services/sts -run '^TestSAMLProbeTrustAWS$' -count=1 -v
STACKD_SAML_AWS_TRUST_PROBE_WRITE=1 STACKD_SAML_AWS_TRUST_USERID_PROBE=1 go test ./internal/services/sts -run '^TestSAMLProbeTrustAWS$' -count=1 -v
```

The replay regenerates locally signed/encrypted test assertions with the same
mutations and compares token errors, extracted fields and derived lifetime caps,
including replay through the generated HTTP SDK handler. Trust probes create a
separate temporary role per condition so update propagation cannot explain the
results; all roles and the provider are deleted and checked for absence.
Separate adversarial tests cover wrapping, duplicate IDs, issuer key isolation,
tampering, inherited namespaces, decryption key rotation and malformed
ciphertexts. They do not use or embed live AWS credentials.
