This directory captures real AWS STS behavior for signed OIDC JWTs. The 186
observations in `aws-initial.json`, `aws.json`, `aws-keys.json`, `aws-trust.json`
and `aws-roles.json` were obtained
on 2026-09-11 through the commercial us-east-1 STS endpoint using AWS CLI 2.36.28.

Each run created its own randomly named S3 bucket, an IAM OIDC provider, and an
IAM role. The bucket policy allowed public reads of only two generated public
JSON objects: issuer discovery metadata and JWKS. Account settings were not
changed. Every created role, provider, object and bucket was deleted; each
fixture records cleanup completion. Returned AWS credentials were never printed
or persisted. The PEM private keys are generated public test material and the
stored JWTs contain only synthetic claims for providers that no longer exist.

The published fixtures are account-anonymized derivatives of those observations.
Account-bearing JWT claims were locally re-signed using the committed test RSA
private key; modified tokens were not submitted to AWS. Other JWT bytes, including
deliberately invalid signatures, are unchanged. IAM identifier account prefixes
and the role account scope use the all-zero fixture account.

`TestOIDCAWSJWTParity` verifies the fixture's signed bytes against the captured keys,
uses the observation timestamp as its clock, and compares retained AWS outcomes and
mapped identity fields. Every successful token is also modified and required to
fail signature verification. Propagation-related IAM AccessDenied responses and
explicit ProviderId routing are separately identified as integration cases.
Those requests are not presented as JWT verifier failures.

`TestOIDCSDKTrustAndProviderRoutingAWSParity` replays the 27 trust and routing
observations from `aws-trust.json` through the real SDK, generated frontend,
unsigned gateway, signature verifier, role trust evaluator and credential store.
Its three setup rows establish IAM propagation. Each of the eleven independently
created test roles had a separate explicit-Federated control statement; every
control succeeded before the corresponding condition or principal was tested.

`TestOIDCSDKAuthorizedRolesAWSParity` replays 31 roles-claim and trust observations
from `aws-roles.json` through the complete API. Nine additional rows record setup
or condition-role propagation. These outcomes depend on the requested role and
are intentionally not classified as JWT-only verifier results. The fixture's
`source_account_id` supplies the all-zero account for role ARNs embedded in the
locally re-signed JWTs; it does not identify the original AWS account.

Observed behavior retained by the verifier:

- RS256, RS384, RS512, ES256, ES384 and ES512 signatures work.
- `iss`, `sub`, `aud`, `iat` and `exp` must be present. Subjects can be empty,
  short, numeric or longer than the response model's suggested limit. Numeric
  subjects become strings; null subjects produce AWS InternalFailure.
- Integer timestamp strings work; fractional timestamps fail. AWS allows five
  minutes of clock tolerance for `iat`, `nbf` and `exp`. Expiration uses the wire
  code `ExpiredTokenException`.
- More than one audience requires `azp`; when present, `azp` determines audience
  registration and the response Audience. A one-element audience array works.
- Nested session tag values must be single-element string arrays. Flattened
  session tag values are strings. Source identity is a signed claim.
- The custom-provider response Provider is the IAM provider ARN. A token with
  only 60 seconds remaining can issue a requested two-hour role session.
- JWT JSON interpretation uses the last duplicate member consistently. The
  verifier never reconstructs or substitutes the bytes covered by the signature.
- JWK key IDs are required. A JWT without a key ID works only with a single
  available indexed signing key. Later duplicate JWK IDs replace earlier keys.
- JWK `alg` does not select the verification hash; the signed JWT `alg` does.
  Encryption-use keys fail. `key_ops` fails even when set to `["verify"]`.
- `x5c` must agree with the public parameters. Certificate-only RSA JWKs fail.
  More than 100 RSA keys prevents RSA tokens while EC tokens remain usable.
- During custom OIDC trust evaluation, `aws:PrincipalAccount` is the provider's
  account, `aws:PrincipalType` is `User`, `aws:userid` is the provider ARN, and
  `aws:PrincipalArn` is absent. An `AWS: "*"` principal does not authorize OIDC.
- Unknown `ProviderId` values return AccessDenied. Passing a JWT with Amazon's
  ProviderId returns InvalidIdentityToken; Facebook's rejection returns
  IDPRejectedClaim. Only Amazon and Facebook opaque tokens use ProviderId.
- The signed `https://aws.amazon.com/roles` claim accepts a string array or
  semicolon-delimited string and matches exact role ARNs. Null acts absent,
  invalid array entries are ignored, and surrounding whitespace is removed.
  Empty/no-valid-ARN claims and nonmatching roles return InvalidIdentityToken.
  `sts:RoleAuthorizedByIdp` is false when absent and true on a match; Bool trust
  conditions distinguish those cases. The key is scoped to WebIdentity requests.

Repeat explicitly with configured real AWS credentials:

```
python scripts/aws/sts_oidc_probe.py
python scripts/aws/sts_oidc_probe.py --key-semantics
python scripts/aws/sts_oidc_probe.py --trust-context
python scripts/aws/sts_oidc_probe.py --authorized-roles
```

The script uses a `finally` cleanup and records failures needing manual cleanup.
Normal tests never run it or contact an issuer.

`AssumeRoleWithWebIdentity` is registered with generated request and response
types. SDK tests use real signatures and issue stored credentials that then sign
GetCallerIdentity requests. They cover session tags, source identity, session
policies, expiry versus role duration, account/partition scope, and provider or
trust changes before issuance. These tests establish the federation path, not
completion of the other STS operations or all IAM permission behavior.

OAuth introspection tests use controlled HTTPS servers and real response parsing.
They cover Login with Amazon tokeninfo and Facebook debug_token, including app
credentials, expiry/rejection, cancellation, token redaction and redirect refusal.
No live social identity account tokens were available; these tests establish the
HTTP boundary rather than AWS OAuth output parity.

Authoritative references:

- https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html
- https://developer.amazon.com/docs/login-with-amazon/implicit-grant.html
- https://developers.facebook.com/docs/graph-api/reference/debug_token/
