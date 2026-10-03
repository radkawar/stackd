# IAM Identity Center

Identity Center uses the AWS-generated `sso-admin`, `sso-oidc`, and `sso` API contracts. Account assignments provision actual IAM roles; the portal exchanges an authorized directory session for actual temporary role credentials. Those credentials use the existing IAM/STS authority when they sign other service requests. There is no separate permission evaluator or CLI-cache injection path.

## Directory and sign-in configuration

`CreateInstance` creates an owned Identity Store directory. Provision users, groups, and memberships with the [Identity Store API](identity-store.md). Instance ownership is scoped by partition, account, and primary Region. Directory IDs from another owner cannot be used to administer that directory.

The local device and authorization-code browsers authenticate against an explicitly configured [Cognito User Pool](cognito.md), using its existing `USER_PASSWORD_AUTH` and `GetUser` flows:

```sh
stackd --database state.sqlite --listen 127.0.0.1:4566 \
  --public-endpoint http://127.0.0.1:4566 \
  --sso-user-pool-client-id "$COGNITO_APP_CLIENT_ID"
```

The app client must allow `USER_PASSWORD_AUTH`; create a confirmed user with a permanent password. Its canonical Cognito username must match the Identity Store `UserName`. The directory supplies identity and group membership; Cognito supplies password authentication. Without the explicit app-client configuration, password authorization is unavailable, not automatically approved. MFA/custom-challenge completion and an external enterprise IdP are not implemented by this local browser integration.

## Unmodified AWS CLI device flow

Use the instance's AWS-shaped **issuer identifier**, independently of the local HTTP transport endpoint. For instance ARN `arn:aws:sso:::instance/ssoins-0123456789abcdef`:

```ini
[sso-session local]
sso_start_url = https://identitycenter.amazonaws.com/ssoins-0123456789abcdef
sso_region = us-east-1
sso_registration_scopes = sso:account:access

[profile local-developer]
sso_session = local
sso_account_id = 123456789012
sso_role_name = Developer
region = us-east-1
```

```sh
export AWS_ENDPOINT_URL=http://127.0.0.1:4566
aws --endpoint-url "$AWS_ENDPOINT_URL" sso login \
  --profile local-developer --use-device-code --no-browser
aws --endpoint-url "$AWS_ENDPOINT_URL" sts get-caller-identity \
  --profile local-developer
```

The configured permission-set name is `sso_role_name`, not the generated `AWSReservedSSO_...` IAM role name. China uses `identitycenter.amazonaws.com.cn`; GovCloud uses `identitycenter.us-gov.amazonaws.com`. The issuer identifies a locally persisted instance; the endpoint override directs API requests locally. No request to a native AWS Identity Center instance is needed. Current AWS CLI versions require an HTTPS AWS-owned issuer/start identifier before constructing OIDC requests; a localhost start URL is therefore not interchangeable with the local transport endpoint.

The CLI prints a local verification URL under `/_stackd/sso/device`. Open that URL in a real browser, verify the displayed terminal code, and authenticate the configured Cognito user. Approval grants that device request once. The CLI itself writes its standard SSO cache and obtains role credentials; do not hand-write cache files or substitute a browser driver for the `aws sso login` command. For HTTPS listeners use `--tls-cert`, `--tls-key`, and the corresponding trusted `AWS_CA_BUNDLE`.

The implemented OAuth paths are public-client registration, S256 authorization-code/PKCE, device authorization/polling, access-token issuance, refresh, and logout. Application-entitled client registration and `CreateTokenWithIAM` remain separate unsupported paths.

## Authorization code and S256 PKCE

Register a public client with `grantTypes: ["authorization_code", "refresh_token"]`, `scopes: ["sso:account:access"]`, the instance's `issuerUrl`, and its `redirectUris`. `RegisterClient.authorizationEndpoint` points to the actual `/authorize` browser endpoint. The issuer is an instance identifier in the client's partition/Region, not the transport endpoint; when registered, it cannot be substituted during authorization or device authorization.

Open the authorization endpoint with `response_type=code`, `client_id`, `redirect_uri`, `code_challenge_method=S256`, the unpadded base64url SHA-256 `code_challenge`, and the caller's `state`. Both the standard `scope` and the AWS CLI's `scopes` spelling are accepted; conflicting values are rejected. Omitted scopes use registered scopes. Registration without an issuer can select the instance using `issuer_url` on this request; a registered issuer cannot be overridden. The configured Cognito login and current directory mapping are the same as the device flow.

Redirect registration accepts HTTPS web/app links, HTTP loopback addresses (IPv4, IPv6, or `localhost`), and reverse-domain private-use schemes such as `com.example.app:/oauth/callback`. User information, fragments, relative URLs, and executable browser schemes are rejected. Registered URLs match exactly except for the loopback IP port, which may be dynamically allocated as required by [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252#section-7.3). This supports the CLI's portless registered callback and ephemeral receiver. The token exchange must supply the **exact URI used by that authorization request**, including its actual port.

After browser approval the registered callback receives a short-lived code and the exact decoded caller state. Denial returns `error=access_denied` and the same state. Invalid client/redirect/challenge requests are rejected locally, never redirected to an untrusted URL. Exchange using `CreateToken` with `grantType=authorization_code`, `clientId`, `clientSecret`, `code`, `redirectUri`, and the original `codeVerifier` (43–128 RFC 7636 unreserved characters). Substituted clients, redirect URIs or verifiers, expired codes, and replay are rejected. The resulting token uses the existing portal/account-role authority, refresh family and logout, not a separate credential mechanism.

Registered callback query bytes are preserved when adding OAuth response
parameters, including valid URI query characters that are not form encoding.
Browser authorization routing does not intercept signed or presigned AWS API
requests at `/authorize`; an S3 bucket with that name remains usable. SDK
regressions cover the callback-query boundary and signed bucket lifecycle on
memory and SQLite.

The unmodified AWS CLI default flow can be invoked with the profile above by **omitting** `--use-device-code`:

```sh
aws --endpoint-url "$AWS_ENDPOINT_URL" sso login \
  --profile local-developer --no-browser
```

The CLI's OIDC endpoint configuration must route its unmodeled `/authorize` browser request to stackd, and the browser must run where the CLI loopback receiver is reachable. Modern CLI versions derive that URL from the configured OIDC endpoint. A proxy or older CLI that instead opens the native regional OIDC host needs browser routing to the local listener; an API-only endpoint override is not proof of PKCE parity.


## Permission sets and current account authority

Implemented administration includes instance and permission-set lifecycle/tags, inline policies, AWS-managed-policy attachments, customer-managed-policy references, permission boundaries, user/group account assignments, provisioning, assignment/provisioning status, and the corresponding list/describe operations. Policy documents are validated through the existing IAM parser. Administrative calls use current IAM authorization, including instance, permission-set and account resource checks and tag/primary-Region context where applicable.

A local instance can target its owning account. Cross-account targets must be ACTIVE members of the same Organizations organization; `sso.amazonaws.com` trusted access must be enabled. The owner must be the management account or a registered delegated administrator. A delegated administrator cannot target the management account. These are live checks against Organizations, not copied account lists.

Creating an assignment provisions an owned IAM role if needed. The role uses `/aws-reserved/sso.amazonaws.com/` in `us-east-1`, with the Region path component elsewhere, and an `AWSReservedSSO_<permission-set-name>_<random-suffix>` name. Updating/provisioning preserves the current role incarnation. Removing the final assignment deletes that owned role; recreating an assignment produces a new role ID and suffix. Ownership checks prevent replacing an unrelated IAM role.

Owned reserved roles reject ordinary IAM trust, policy, boundary, duration, metadata and lifecycle mutations with `UnmodifiableEntity`, even for an otherwise authorized administrator. Changes must go through Identity Center provisioning/removal. Protection comes from the retained Identity Center ownership, not a role-name prefix. These roles are **not service-linked roles** and their sessions remain subject to SCP/RCP controls.

Permission-set deletion also rechecks current Organizations eligibility for every provisioned target, including permission sets provisioned without assignments. Loss of trusted access or delegated authority rejects deletion and rolls back all role/provisioning effects across accounts. Its IAM resource checks remain the documented Instance and PermissionSet resources; deletion does not invent an additional Account-resource permission requirement.

Permission-set edits are pending configuration until `ProvisionPermissionSet` updates the actual role. Existing assignments do not silently apply a pending policy or duration change. AWS-managed policies, target-account customer-managed policies, boundaries, trust, and role session duration are enforced by the current IAM authority. Status records report `SUCCEEDED` only after the synchronous real provisioning/deletion transaction succeeds; the implementation does not fabricate delayed success jobs.

`ListAccounts`, `ListAccountRoles`, and `GetRoleCredentials` resolve the current directory user, direct assignments, group memberships, Organizations eligibility, and current provisioning. Removing membership/assignment or deleting the user prevents new exchanges. Already-issued IAM sessions remain subject to current IAM policy, trust, role incarnation, and expiry. Portal account records currently contain account IDs, not optional display names/email addresses.

## Session and persistence semantics

Memory and SQLite repositories use the same typed shared-domain transaction contract. SQLite stores normalized instances/tags, permission sets/policies/boundaries/tags, assignments, provisionings, operations, clients/scopes/grant types/redirect URIs/issuer, devices, authorization requests/codes, and sessions. It does not store opaque AWS request/response resource blobs. Administrative changes join directory and IAM effects in the same transaction domain.

Client secrets, device codes, authorization codes, access tokens, and refresh tokens are stored as hashes. Browser passwords and OAuth bearer material are excluded from diagnostic events. Browser forms have an expiring request, per-form CSRF nonce/cookie, same-origin validation, no-store responses, and a restrictive content security policy. Authentication itself is performed outside the state transaction; the current directory identity is checked again when applying approval. PKCE requests retain their exact redirect URI, challenge, scopes, client, issuer instance, caller state and approved directory identity. Pending login forms expire after ten minutes; an approved authorization code expires after five minutes and is redeemed atomically once.

Device codes expire after ten minutes and enforce polling admission, including persisted `authorization_pending`/`slow_down` transitions. A code can be redeemed only once. Client registrations expire after 90 days. Access tokens last one hour and the sign-in/refresh family lasts eight hours; refreshing does not extend an older access token's own expiry. Logout revokes the whole sign-in family, including its refresh authority. Consistent with AWS's documented Logout contract, **logout does not revoke already-issued IAM role sessions**: those credentials retain their original IAM expiry and current IAM constraints.

The SQLite backend retains pending device/PKCE authorization, unredeemed authorization codes, client registration, sign-in families, assignments, provisioned roles, and temporary IAM sessions across controller process restart. Deleting an instance requires removal of permission sets/provisionings and then removes its exact-owned directory rows. Browser and OAuth state no longer resolves a deleted instance/user.

Administration and portal list tokens bind effective request scope and filters
and continue from stable ordered keys, not offsets. Inserting or deleting earlier
rows does not repeat or skip surviving later rows; tokens survive reconstruction.
SSO Admin access-denied, conflict and missing-resource errors use documented HTTP
400. Identity Store's existing 400 client-error contracts remain unchanged;
generated HTTP-status hints do not override the primary API references.

## Evidence and boundaries

`scripts/identity_center_smoke.py` drives a disposable actual executable with SQLite, a trusted local TLS certificate, SDK-created directory/Cognito/organization/permission-set resources, and the real AWS CLI. Run it with `--binary`, `--state-directory`, and, when a version-manager shim depends on the original HOME, `--aws-cli /absolute/path/to/aws`. It waits for a real browser at the printed URL. Its private state directory contains authentication material; retain only sanitized `evidence.json`, then delete the entire directory. The native AWS SSO/Organizations baseline is not mutated by this probe.

Pass `--pkce` to that same executable/browser smoke to run the unmodified CLI's default authorization-code flow, including its real loopback receiver and subsequent signed account-role requests. The dedicated `TestIdentityCenterPKCEBrowserBindingAndRestart` SDK regression exercises real Cognito authentication, memory/SQLite reconstruction of pending forms, authorized codes and sessions, CSRF, exact state, verifier/client/redirect binding, rejection of unknown redirect targets, denial, code expiry/replay and actual STS identity from portal role credentials. Neither path injects CLI cache contents.

The [retained PKCE evidence](../testdata/integration/identity_center_pkce_local.json) records successful unmodified AWS CLI 2.36.28 default login through Chromium and its actual loopback receiver, signed S3 writes in two accounts, retained credentials after restart, current-policy/membership enforcement, logout, and four clean controller exits. The browser visibly reached the CLI-owned credential-sharing success page. This smoke also caught and fixed a browser-only restriction: Chromium applies `form-action` CSP to the POST's redirect chain, so PKCE pages allow self plus the validated callback origin; device pages remain self-only.

The [retained local evidence](../testdata/integration/identity_center_local.json) records unmodified AWS CLI 2.36.28 login through the actual browser, pending-device and credential process restarts, signed S3 requests in two accounts, live policy and group-membership changes, new role incarnation after final-assignment deletion, server-side logout/refresh rejection, device/role expiry, and four clean controller exits. The browser's successful authorization page was also visually observed. The probe never writes a CLI token/credential cache itself.

Consumer-visible regressions cover polling admission and expiry, concurrent one-time redemption, refresh-family logout, old-access-token expiry, current directory deletion, and partition/Region/issuer binding. IAM provisioning regressions separately cover role incarnation, ownership, current policy/trust, and permission-set duration activation.

The [authority-boundary smoke evidence](../testdata/integration/identity_center_authority_local.json) records signed IAM/STS rejection against actual protected roles, successful trusted provisioning, rollback after delegated-authority revocation, process restart, and successful deletion after authority restoration by a caller scoped only to the documented instance/permission-set resources. Permanent SDK regressions reproduce the pre-fix public mutations and unauthorized deletion, exercise memory/SQLite, and separately cover trusted-access loss.

Explicit remaining boundaries:

- `CreateTokenWithIAM`, applications/application assignments, application-entitled client registration, trusted token issuers, and access-control attributes/ABAC require their actual consumer flows and are not claimed implemented.
- Customer-managed KMS instance configuration, disabled permission sets, latest-permission-set provisioning-status filtering, and AWS asynchronous propagation/quotas are not implemented. Unsupported configuration is rejected rather than silently persisted.
- Native OIDC/portal audit selection and identity projection are not calibrated. SSO administration uses the shared management event recorder; bearer/password material is not emitted as diagnostic events.
- Native AWS organization/SSO administrative baselines were deliberately left untouched. Directory read-only fixtures and the separate [Cognito Identity native probes](cognito-identity.md) do not establish full native Identity Center parity.

## Primary contracts

- [IAM Identity Center OIDC StartDeviceAuthorization](https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_StartDeviceAuthorization.html)
- [OIDC public-client registration](https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_RegisterClient.html)
- [OAuth native-app redirect URI types and loopback ports](https://www.rfc-editor.org/rfc/rfc8252)
- [PKCE S256 and verifier syntax](https://www.rfc-editor.org/rfc/rfc7636)
- [AWS CLI default PKCE endpoint and registration implementation](https://github.com/aws/aws-cli/blob/v2/awscli/botocore/utils.py)
- [OIDC CreateToken](https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_CreateToken.html)
- [Portal Logout and existing IAM role sessions](https://docs.aws.amazon.com/singlesignon/latest/PortalAPIReference/API_Logout.html)
- [IAM Identity Center actions, resources, and condition keys](https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsiamidentitycenter.html)
- [Protected AWSReservedSSO roles](https://docs.aws.amazon.com/singlesignon/latest/userguide/troubleshooting.html#issue4)
- [AWS CLI SSO issuer/start-URL resolution](https://github.com/aws/aws-cli/blob/v2/awscli/customizations/sso/resolve.py)
