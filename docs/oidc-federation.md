# OIDC web identity federation

`AssumeRoleWithWebIdentity` accepts unsigned AWS Query requests through the
generated STS input model. The gateway permits anonymous requests only for the
two modeled federation operations. Other actions require SigV4. Partial signing
material, duplicate parameters, conflicting protocol headers, invalid versions
and oversized request bodies fail before reaching token authentication.
`Config.UnsignedRegion` supplies the trusted endpoint region for unsigned
requests and defaults to `us-east-1`; token claims and query parameters cannot
change `aws:RequestedRegion`.

Custom providers are looked up in the validated role ARN's account and
partition. Token claims supply no AWS root, IAM user or role identity. STS checks
the issuer, registered audience (or `azp`), timestamps and RSA/ECDSA signature
against the configured provider's public keys. It supports RS256/384/512 and
ES256/384/512. Token-supplied key URLs and embedded keys cannot introduce trust.

Provider discovery is an explicit dependency. Configure `Config.OIDCDiscovery`
with a controlled source for offline use, or construct a network source with
`NewHTTPOIDCDiscovery`. The default does not contact external issuers. Discovery
runs outside IAM transactions; cached keys are bound to the provider's immutable
ID and configuration version. A failed verification using cached keys gets one
refresh attempt. Canceled requests stop waiting, and changed/deleted providers
cannot issue credentials using their previous configuration.

The common federation authority validates the current provider and role trust
policy and inserts credentials in one IAM storage transaction. Trust must allow
`sts:AssumeRoleWithWebIdentity`, plus `sts:TagSession` and
`sts:SetSourceIdentity` when the signed token requests those features. Inline
and managed session policies restrict the issued role session. Verified session
tags, transitive tag names and source identity survive issuance. Only documented
claims available in sessions become downstream IAM condition keys.

The signed `https://aws.amazon.com/roles` claim can restrict a token to exact IAM
role ARNs, using a JSON array or semicolon-delimited string. An absent or null
claim sets the WebIdentity-only `sts:RoleAuthorizedByIdp` trust condition to
false. A matching claim sets it to true; a present, nonmatching claim returns
InvalidIdentityToken. Invalid array entries are ignored, surrounding whitespace
is removed, and a claim with no valid role ARNs is rejected. This flag is computed
after signature verification and cannot be supplied as an arbitrary claim or
query parameter. It is not retained as downstream session context.

The default session duration is one hour, with a 900-second minimum and the
role's configured maximum (at most twelve hours). JWT expiration determines
whether authentication is valid; it does not cap the lifetime of newly issued
credentials. Custom-provider responses return the IAM provider ARN in
`Provider`, as observed on AWS. Google and Cognito use their fixed built-in
provider names and explicitly configured key discovery.

Opaque Login with Amazon and Facebook tokens require their exact `ProviderId`
and `Config.OAuthTokens`. `NewHTTPOAuthTokenSource` provides bounded HTTPS
introspection; Facebook additionally needs a configured app access token.
Redirects are refused and errors do not expose submitted tokens or configured
credentials. Controlled HTTPS tests cover successful introspection and failures;
no live social-account success token was available for AWS parity capture.

The checked-in [AWS fixtures](../internal/services/sts/testdata/oidc/README.md)
contain 186 observations, including exact JWT bytes, signing keys, timestamps,
errors, trust policies and cleanup provenance. All normal tests run offline.
The optional probe script creates only uniquely owned IAM resources and an S3
bucket exposing two public metadata objects, then deletes and verifies absence
of those resources. It does not change account-wide settings.

Federation integration does not establish complete STS parity. The existing STS
work list still tracks newer token operations, trusted context assertions and
exact AWS packed-policy size calibration.

References: [STS API](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html),
[OIDC condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html),
[session tags](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html).
