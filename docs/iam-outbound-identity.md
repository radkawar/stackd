# Outbound identity federation

IAM owns account-scoped issuer configuration and signing keys. STS
`GetWebIdentityToken` issues an actual signed JWT that an external application
can verify through the public discovery and JWKS endpoints. The three IAM
configuration APIs and STS operation use generated Smithy request/response
bindings. This does not complete the IAM or STS service audits.

## Endpoint configuration

The CLI derives its public HTTP origin from the bound listener. Use
`-public-endpoint https://stackd.example.test` when a proxy or another hostname
serves the endpoint. Embedders supply `Config.PublicEndpoint` before constructing
the stack; bind the listener first when using an ephemeral port. The configured
origin must serve the stack and remain stable when reusing `Config.Storage`.
Request `Host` and forwarded headers do not select an issuer.

An issuer has this local URL:

```text
{PublicEndpoint}/_stackd/oidc/{partition}/{accountID}/{issuerID}
```

Its `/.well-known/openid-configuration` and `/.well-known/jwks.json` endpoints
are public GET/HEAD resources. Discovery names the exact issuer and key endpoint;
JWKS exposes public RSA-2048 and P-384 keys. This local route substitutes for
AWS's account-specific `*.tokens.sts.global.api.aws` hostname. It requires no
network access by stackd and does not weaken inbound HTTPS discovery checks.

Enabling requires a configured public endpoint. Enabling twice returns
`FeatureEnabled`/409. Reading or disabling an inactive feature returns
`FeatureDisabled`/404. Disable retains issuer identity and public keys, so earlier
tokens remain verifiable. Re-enable reuses that issuer. Account/partition
settings and key material use the typed IAM repository, including detached
copies and transactional rollback.

## Configuration propagation

IAM reports the new configuration immediately. STS observes each accepted enable
or disable **10 seconds later in service time**. With a manual clock, advance it
to the deadline before expecting the new vending state. With the real clock,
ordinary requests observe the change after that interval.

This interval is a deterministic model calibrated from the owned AWS capture,
not a promised AWS latency. In `us-east-1`, `eu-west-2` and `us-west-2`, first
successful enable observations arrived about 8.6–11.6 seconds after the IAM
response; disable and re-enable observations arrived about 8.1–9.2 seconds later.
The capture includes transient STS `InternalFailure` responses during transitions;
it does not establish an error frequency or a regional propagation guarantee.

Rapid toggles preserve order. Disabling, then re-enabling two seconds later can
produce a delayed disabled interval even while IAM already reports enabled. The
AWS capture observed that interval. Stackd stores the ordered pending changes
with IAM settings and evaluates their visibility at the signing transaction's
captured time. Failed writes publish no changes. Reconstructing a stack with the
same backend and clock preserves the timeline.

These changes have no external delivery effect: evaluating service time on read
is sufficient, as for credential expiry. They do not need a timer or background
worker. This does not implement the planned shared event journal or durable
scheduler; the memory backend still does not survive a process crash.

## Issuance and authorization

`GetWebIdentityToken` is regional; AWS's global STS endpoint rejects it. Current
IAM user credentials, `GetSessionToken` sessions and assumed roles can issue
tokens. Federated-user credentials from `GetFederationToken` cannot.

The current caller needs `sts:GetWebIdentityToken` on
`arn:{partition}:sts::{accountID}:self`. Requests with tags additionally need
`sts:TagGetWebIdentityToken` on the same resource. The live capture confirms
exact `self` grants work even though the authorization-reference table omits a
resource type. IAM feature configuration uses resource `*`. Identity policies,
permissions boundaries, session policies and Organizations SCPs apply.

Conditions include `sts:IdentityTokenAudience`, `sts:SigningAlgorithm`,
`sts:DurationSeconds`, `aws:RequestTag/<key>` and `aws:TagKeys`. Organizations
supplies `aws:PrincipalOrgID` and `aws:PrincipalOrgPaths`; callers cannot inject
these values. Session tag overrides use the same case-insensitive merge as IAM
evaluation while retaining the winning tag spelling in JWTs.

The signed-session authority re-resolves the caller and current policies under
one IAM transaction. Its Organizations snapshot joins the same memory domain,
pinning both SCPs and membership through publication. Signing reads the propagated vending state and
private keys from that IAM transaction. A canceled or failed commit releases no
token. No bearer token, JWT ledger or additional AWS credential row is persisted.
Replacement backends must preserve the shared transaction context.

Durations are 60–3600 seconds, defaulting to 300. A request extending beyond a
parent session expires with `SessionDurationEscalationException`/403; it is not
silently shortened. Service time determines issue/expiry timestamps. Both
RS256 and ES384 signatures use their actual algorithms, with JOSE fixed-width
`R || S` encoding for ECDSA.

The observed decoded payload limit is **14,984 UTF-8 bytes**. The next byte
returns `JWTPayloadSizeExceededException`/400 for both algorithms. This is the
claims JSON size, not compact token length. The boundary was captured with
different user/role claims and with Unicode and escaped quotes. The model's
audience, tag and duration constraints are enforced by the generated frontend;
case-insensitive duplicate tag keys return `InvalidParameterValue`/400.

## Claims

Standard claims are `iss`, `sub`, `aud`, `iat`, `exp` and a unique UUID `jti`.
One audience is a string; multiple audiences are an array and duplicates remain.
An assumed role's subject is its IAM role ARN, including its path. NumericDate
claims use whole seconds; the API expiration retains subsecond precision.

The `https://sts.amazonaws.com/` object contains:

| Claim | Source |
| --- | --- |
| `aws_account`, `source_region` | Authenticated account and signed request region |
| `principal_id` | Same current IAM principal ARN used for `sub` |
| `org_id`, `ou_path` | Current Organizations membership; `ou_path` is an array of paths ending in `/`, without the account ID |
| `principal_tags` | Current IAM tags merged with authenticated session overrides |
| `request_tags` | Authorized tags supplied to this operation, including accepted `aws:` names |
| `original_session_exp` | Parent session expiry as RFC3339, including IAM user sessions |
| `source_identity` | Authenticated session source identity, when present |
| `federated_provider` | Provider identity retained by the actual OIDC/SAML role issuer |

Claims without a current source are omitted. Future compute/Identity Center
services must supply their real credential context; this implementation does
not fabricate EC2, Lambda, Glue or Identity Center attributes. Outbound tokens
cannot be recycled into `AssumeRoleWithWebIdentity`, including when the issuer
is another account in the same stack. AWS documents this restriction explicitly.

## Evidence and remaining audit

`scripts/aws/iam_outbound_identity_probe.py` captures signed Query behavior. Its
default mode leaves account configuration unchanged. Explicit `--issuance` mode
requires initially disabled outbound federation, enables it temporarily, uses
owned users/roles, then disables it and verifies cleanup. The AWS-assigned issuer
may remain allocated after disable. Credentials and bearer tokens stay in memory;
fixtures retain decoded claims, sizes, public keys and modeled results.

- `testdata/aws/iam/outbound_identity.json`: 65 observations covering validation,
  permissions, boundaries, session policy restrictions, exact resource grants,
  tags, condition keys, caller types and disabled/global endpoint errors.
- `testdata/aws/iam/outbound_issuance.json`: 50 observations covering successful
  user/session/role issuance, both algorithms, actual discovery documents,
  payload boundaries and configuration transitions. Final configuration is
  verified disabled; owned identities are verified deleted.
- `testdata/aws/iam/outbound_lifecycle.json`: 95 observations from
  `scripts/aws/iam_outbound_lifecycle_probe.py`, captured on 2026-09-11. The probe
  temporarily enables the initially disabled feature, samples three STS regions,
  checks public key continuity, then observes a rapid disable/re-enable in
  `us-east-1`. Final configuration is verified disabled. No existing identity
  policies are changed; only token issuer, key ID and timestamps are retained.
- `outbound_identity_*test.go`: actual SDK requests, external public-key
  verification, fixture replay, payload limits, current IAM/Organizations
  claims, expiry, revocation, concurrent policy/configuration changes and failed
  publication, ordered propagation, reconstruction and partition isolation.
  `integration/outbound_federation_integration_test.go` exercises the inbound
  OIDC → role credential → outbound JWT relationship.
- Organizations tests move a member during an active decision and verify its
  pinned membership and next-request ancestry. Authorization tests reject forged
  organization attributes.

Signing-key rotation/retention and partition-specific wire behavior still need
their lifecycle audit. The capture confirms stable keys while disabled and after
re-enable within its observation window; it cannot establish a rotation schedule
or long-term retention. AWS documents availability in commercial, China and
GovCloud regions in its [launch announcement](https://aws.amazon.com/blogs/aws/simplify-access-to-external-services-using-aws-iam-outbound-identity-federation/).
Local tests verify separate settings, issuers and principal ARNs across those
partitions; the live fixtures cover only the commercial partition. Unobserved
root/Identity Center/compute-specific claim cases remain within the open IAM audit.

Primary references: [IAM enable](https://docs.aws.amazon.com/IAM/latest/APIReference/API_EnableOutboundWebIdentityFederation.html),
[IAM disable](https://docs.aws.amazon.com/IAM/latest/APIReference/API_DisableOutboundWebIdentityFederation.html),
[IAM status](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetOutboundWebIdentityFederationInfo.html),
[STS token API](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetWebIdentityToken.html),
[outbound setup and inbound restriction](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound_getting_started.html),
[claims](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound_token_claims.html),
and [permission controls](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound_policies.html).
The guide's illustrative `IssuerUrl`/`IdentityToken` response names disagree with
the API/SDK contracts and captured `IssuerIdentifier`/`WebIdentityToken`; the
implementation follows the latter. Several claim encodings above also refine
the guide using direct AWS observations.

Protocol contracts come from the pinned SDK models recorded in generated file headers.
