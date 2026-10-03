# Cognito Identity pools

> In native capture references, `000000000000` is an anonymized account alias,
> not the AWS account originally used. See [capture privacy](behavior-references.md#publishing-sanitized-probe-captures).

Cognito Identity is a separate regional owner from [Cognito user pools](cognito.md).
The enhanced authentication flow exchanges a verified user-pool ID token, or an
allowed guest identity, for real shared STS credentials. It does not manufacture
an IAM caller from a pool ID, token payload, account parameter or role ARN.

## Supported application boundary

The owner implements pool create/update/describe/list/delete, pool tags,
`GetId`, `GetCredentialsForIdentity`, identity describe/list/delete/unlink, and
pool-role get/set, and principal-tag attribute map get/set. Pool and identity IDs use `Region:UUID`. Administrative calls
use current IAM authorization; attaching default and mapped roles also requires
current `iam:PassRole`. Pool/account/Region/partition scope is retained, and list
cursors bind the operation and owner rather than using mutable row offsets.

`GetId` with a verified login returns its retained identity. Guest calls create
independent identities. A guest can acquire a verified login; if that login
already belongs to a retained authenticated identity, credential exchange returns
that canonical identity. Conflicting authenticated bindings return a
`ResourceConflictException`, not a fabricated merge. An authenticated identity
cannot obtain credentials by omitting its login.

The provider key is the ordinary AWS user-pool name, for example
`cognito-idp.us-east-1.amazonaws.com/us-east-1_example`. Its configured app client
must match the token audience. Verification reuses the user-pool owner's actual
signing material, shared JWT signature verifier and retained authentication
families. The issuer, ID-token use, subject, audience, signature, issuance time
and exclusive expiry deadline are checked. Access tokens cannot substitute for
ID tokens. `ServerSideTokenCheck` additionally rejects deleted/disabled users and
revoked/global-signout families. With that option disabled, signing keys are not
revoked by sign-out: valid offline JWTs remain usable until expiry. Identity
login bindings retain provider/subject, never raw tokens.

Tokens are reusable bearer credentials until their validity boundary; ordinary
repeat exchange is not treated as a one-time-code replay attack. A revoked token
cannot be replayed through server-side checking. Issued STS credentials have their
own lifetime: token revocation/expiry prevents another exchange, rather than
silently revoking an already-issued session.

## Roles and current IAM

Unauthenticated exchanges choose `Roles["unauthenticated"]`. Authenticated
exchanges choose the default authenticated role or the provider/client-specific
role mapping:

- `Token` uses verified `cognito:preferred_role`/`cognito:roles` claims and accepts
  `CustomRoleArn` only when that role appears in the token's allowed roles.
- `Rules` evaluates ordered string-claim rules with `Equals`, `NotEqual`,
  `StartsWith` and `Contains`; `Contains` also matches string-array claims such
  as `cognito:groups`. Missing claims do not match `NotEqual`. As native AWS
  requires, supplying `CustomRoleArn` with Rules returns `InvalidParameterException`.
- Unresolved mappings use the configured authenticated default or deny.
- Multiple logins selecting different roles are rejected.

Enhanced-flow roles must belong to the pool account. Role trust is evaluated by
existing STS/IAM authority for federated principal
`cognito-identity.amazonaws.com`, with the pool `aud`, identity `sub`, and
`authenticated` or `unauthenticated` `amr`. This is not another policy evaluator.
The shared federation transaction rereads the role and trust policy, applies
resource controls and inserts ordinary credentials. Signed downstream requests
therefore see current role policy changes, session scope and expiry.

## Principal tags and attribute-based access

`SetPrincipalTagAttributeMap` and `GetPrincipalTagAttributeMap` authorize the
current IAM caller against the identity pool. Mappings belong to the pool account,
Region and configured user-pool provider, not globally to a token issuer. Custom
maps bind tag keys to verified ID-token claim names. `UseDefaults: true` selects
`{"client":"aud","username":"sub"}` and overrides a supplied custom map. Setting
`UseDefaults: false` with an empty or omitted map disables mapping; subsequent
Get returns `ResourceNotFoundException`. These exact responses were captured
from native AWS in `testdata/integration/cognito_identity_principal_tags_native.json`.

Enhanced credential exchange supplies mapped values to the existing STS
federation authority as session tags. The role trust must permit both
`sts:AssumeRoleWithWebIdentity` and `sts:TagSession`; tags are never silently
dropped to bypass trust. IAM and resource policies can use
`aws:PrincipalTag/<key>` on real signed downstream requests. Unmapped providers
and guest exchanges retain their untagged behavior.

Mappings accept up to 50 unique case-insensitive tag keys (128 characters),
excluding the reserved `aws:` prefix, and claim names up to 256 characters.
Mapped scalar strings, booleans and finite JSON numbers become string values.
Values must meet STS tag character and 256-character limits. Missing, null,
array/object, invalid or oversized mapped claims fail closed, as do conflicting
tags from multiple logins. This conservative invalid-claim behavior is not
claimed as native claim-coercion parity.

Remapping or disabling affects newly issued credentials, never rewrites existing
sessions. User sign-out prevents a new exchange when server-side token checks
are enabled, but does not mutate existing STS sessions. Removing a configured
provider removes its mapping; deleting the pool removes all its maps. Claims
used as authorization boundaries must not be user-writable through any app
client. See the official
[attribute access-control guidance](https://docs.aws.amazon.com/cognito/latest/developerguide/attributes-for-access-control.html),
[map API](https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_SetPrincipalTagAttributeMap.html)
and [STS session-tag limits](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html).

## Persistence and transaction ownership

`storage/cognitoidentity` exposes the typed repository. Memory uses the shared
clone-and-commit domain. SQLite uses service-owned SQLC queries and
schemas `252_cognitoidentity.sql` and `308_cognitoidentity_principal_tags.sql`, joined to the same transaction as Cognito,
IAM, credentials and API events. Pool names/flags, provider configuration,
tags, roles, role mappings and typed provider principal-tag maps have their own columns; identities and unique
provider/subject bindings have separate indexed tables. Nested generated
configuration fields use JSON, not opaque whole-resource documents.

Pool deletion cascades through identities and login bindings. Public resource
resolution supplies audit recipient scope only; it never grants IAM authority.
API events redact login tokens and omit credential material. STS session events
and the outer identity transition commit together.

## Evidence

Primary behavior references:

- [GetCredentialsForIdentity](https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_GetCredentialsForIdentity.html)
- [CognitoIdentityProvider and server-side checks](https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_CognitoIdentityProvider.html)
- [Role-based access control](https://docs.aws.amazon.com/cognito/latest/developerguide/role-based-access-control.html)
- [IAM trust roles](https://docs.aws.amazon.com/cognito/latest/developerguide/iam-roles.html)
- [Enhanced and classic authentication flows](https://docs.aws.amazon.com/cognito/latest/developerguide/authentication-flow.html)

The generated frontend comes from the repository's pinned AWS SDK Smithy model;
operation registration alone is not behavioral evidence.

`testdata/integration/cognito_identity_native.json` records the exact-owned
2026-09-28 native probe in account `000000000000`, `us-east-1`:

- A Cognito user-pool ID token repeatedly resolved to the same identity.
- Guest and authenticated exchanges both produced credentials that signed
  successful S3 `ListBuckets` requests.
- Missing authenticated login and global-signout replay returned
  `NotAuthorizedException`.
- An existing issued credential observed a current role-policy `AccessDenied`.
- Replacing current trust with Deny caused another exchange to return
  `InvalidIdentityPoolConfigurationException`.
- The identity pool, user pool (including app client/user), role and inline
  policy were all deleted. The fixture retains exact cleanup IDs, no secrets.

`testdata/integration/cognito_identity_roles_native.json` records a second
exact-owned native calibration: `Contains` matched a Cognito groups array and
selected the mapped role; `CustomRoleArn` with Rules returned
`InvalidParameterException`. Both roles and both pools (including client/user/group)
were deleted. The regression first reproduced the local wrong-default-role result,
then passed after the array-claim correction.

The bounded native probe source is `scripts/cognito_identity_probe.py` and requires
explicit account verification before mutation. `scripts/cognito_identity_smoke.py`
runs an actual stackd executable with an isolated SQLite database and exercises
SDK exchange, signed S3 object bytes, controller restart and current-authority
rejections. `integration/cognito_identity_test.go` is the Go SDK regression path
for memory/SQLite, actual signed SQS message bodies, scopes, token/rule roles,
token checks and restart. `integration/cognito_identity_controls_test.go` covers
pool update/list pagination, request-tag IAM conditions and retained identities.
The Cognito Identity SDK regressions passed on memory and reopened SQLite on
2026-10-01, including eight concurrent first-login `GetId` calls and
`integration/cognito_identity_principal_tags_test.go` coverage of map
replacement/reset, default precedence, current IAM, account/Region/provider/pool
isolation, restart and provider/pool cleanup. The actual executable smoke passed
with two normal controller exits. It exercised a real S3 bucket policy using
`aws:PrincipalTag/application`, rejected missing `sts:TagSession`, retained maps
across process restart, denied fresh remapped/reset credentials, and preserved
old session tags through remapping and user sign-out. Its sanitized output is
retained in `testdata/integration/cognito_identity_local.json`.
The original end-to-end attempt exposed missing anonymous gateway routing; the
shared gateway now selects the generated Cognito Identity optional-auth contract
instead of requiring SigV4 for public exchanges.

Reproduce these exercised workflows with:

```sh
go test ./internal/services/cognitoidentity ./integration -run 'Test(CognitoIdentity|Principal)' -count=1
python3 -B -P scripts/cognito_identity_smoke.py --binary /path/to/stackd
```

## Explicit remaining boundaries

Classic `GetOpenIdToken`, developer identities, external OIDC/SAML/social identity
providers and developer merge/lookup/unlink operations
return explicit unsupported errors. Active pool configuration requiring these
unimplemented owners is rejected, not stored as if authentication worked.
Numeric/object rule claims, non-Contains array comparisons, automatic merging of
conflicting authenticated identities, disabled-identity filtering, AWS propagation
latency, quotas/throttling, noncommercial endpoint calibration and complete audit
parity remain outside the exercised boundary. These are not claims of full
Cognito Identity parity.

Intentional implementation markers are in
`internal/services/cognitoidentity/pools.go` for classic/developer/external-provider
verification and `internal/services/cognitoidentity/service.go` for unsupported
classic/developer workflows. No native resources remain from the recorded probes.
