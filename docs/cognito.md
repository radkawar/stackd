# Cognito user pools

The generated AWS JSON 1.1 `cognitoidp` frontend models 132 operations and uses
`cognito-idp` as its signing name. The current application kernel implements 54
pool, app-client, user, group, authentication and email operations. Other modeled operations
return explicit protocol errors, not empty successes. This is not complete
Cognito, and it does not implement Cognito Identity pools.

This document owns the current behavior and evidence boundaries;
[TODO.md](../TODO.md) tracks remaining work and the generated
[service inventory](services.json) tracks operation registration, not parity.

## Reachable operations

| Owner | Implemented operations |
| --- | --- |
| Pools and tags (9) | `CreateUserPool`, `DescribeUserPool`, `UpdateUserPool`, `DeleteUserPool`, `ListUserPools`, `AddCustomAttributes`, `ListTagsForResource`, `TagResource`, `UntagResource` |
| App clients (5) | `CreateUserPoolClient`, `DescribeUserPoolClient`, `UpdateUserPoolClient`, `DeleteUserPoolClient`, `ListUserPoolClients` |
| Administrative users (10) | `AdminCreateUser`, `AdminGetUser`, `AdminDeleteUser`, `AdminEnableUser`, `AdminDisableUser`, `AdminSetUserPassword`, `AdminConfirmSignUp`, `AdminUpdateUserAttributes`, `AdminDeleteUserAttributes`, `ListUsers` |
| Groups and membership (9) | `CreateGroup`, `GetGroup`, `UpdateGroup`, `DeleteGroup`, `ListGroups`, `AdminAddUserToGroup`, `AdminRemoveUserFromGroup`, `AdminListGroupsForUser`, `ListUsersInGroup` |
| Authentication and public users (13) | `InitiateAuth`, `AdminInitiateAuth`, `RespondToAuthChallenge`, `AdminRespondToAuthChallenge`, `RevokeToken`, `GlobalSignOut`, `AdminUserGlobalSignOut`, `GetUser`, `ChangePassword`, `SignUp`, `UpdateUserAttributes`, `DeleteUserAttributes`, `DeleteUser` |
| Email verification and recovery (7) | `ConfirmSignUp`, `ResendConfirmationCode`, `ForgotPassword`, `ConfirmForgotPassword`, `GetUserAttributeVerificationCode`, `VerifyUserAttribute`, `AdminResetUserPassword` |

Pool configuration includes password policies, user schema, supported username and
alias settings, tags and deletion protection. App clients govern enabled login
flows, attribute visibility/writes, secret hashes, token lifetimes and user
existence protection. Unsupported active configurations are rejected rather than
retained as promises of behavior.

## Captured email delivery

Email delivery uses the same SES durable message repository as classic AWS Query
and SES v2 application sends. Accepted messages contain actual RFC 5322 MIME;
the post-commit scheduler atomically writes readable `.eml` files. The CLI
defaults to `<database>.ses/<partition>/<account>/<region>/<message-id>.eml`.
Use `-ses-email-directory` to choose another directory, including for a memory
stack, or set `stackd.Config.SESEmailDirectory` when embedding. Files contain
private email content and authentication codes: protect this directory and the
database. This is local capture, not SMTP or Internet delivery.

`AutoVerifiedAttributes=["email"]` causes signup and email-address changes to
queue verification mail. `ConfirmSignUp` and `VerifyUserAttribute` consume the
actual code from that captured message; `ResendConfirmationCode` replaces the
old code. Verification codes expire after 24 hours of service time. Password
recovery uses the configured priority and a verified email address; its codes
expire after one hour. A selected SMS recovery channel fails explicitly rather
than silently falling back to email. Successful reset revokes prior sessions.
Codes belong to the pool/user, not the requesting app client: a replacement
client can confirm a pending signup, and administrative reset needs no client.
Wrong, expired, consumed, or destination-changed codes cannot perform the transition.

`AdminCreateUser` supports email invitations with
`DesiredDeliveryMediums=["EMAIL"]`, and `MessageAction=RESEND` renews an existing
temporary-password invitation. `SUPPRESS` still sends nothing. Signup without
automatic verification remains unconfirmed without a code; `AdminConfirmSignUp`
remains available. User/code writes and durable email acceptance share the same
transaction. Delivery admission failure does not leave a created user or usable
code; capture I/O failure retains a retryable message after commit.

The default `COGNITO_DEFAULT` sender is `no-reply@verificationemail.com`.
Its managed authority is internal to Cognito and cannot authorize public SES
requests. `DEVELOPER` requires a verified same-account, same-region SES email
identity and uses the actual Cognito email service-linked role. Pool configuration
uses caller IAM permission to create that role; delivery resolves current role
authority, identity state, account/configuration sending settings and sandbox
recipient restrictions. Optional developer `From`, reply-to and configuration
set are forwarded. Cross-region source identities, custom default sender/reply-to,
custom invitation/verification templates, verification links and SMS remain
explicitly unsupported. Existence-protected missing-user responses do not create
phantom users, codes or messages.

Missing `DEVELOPER` source identities or configuration sets return
`InvalidParameterException` (HTTP 400), not an opaque internal error. An existing
unverified identity still returns `MessageRejected`; repository faults remain
`InternalErrorException` (HTTP 500). The missing-resource classification follows
the documented configuration and modeled client-error contracts; the exact
native AWS code for this missing-identity case has not been captured.

To complete **local SES email-identity verification**, configure the capture
directory above, then:

```sh
aws --endpoint-url http://127.0.0.1:4567 --region us-east-2 \
  sesv2 create-email-identity --email-identity sender@example.com
```

Open its captured `Amazon SES Email Address Verification Request` message.
Decode the MIME body (it can be quoted-printable), and open the advertised
`/_stackd/ses/verify-email-identity?token=...` URL. The first use succeeds; replay
or use after 24 hours of service time fails. `get-email-identity` then reports
`VerifiedForSendingStatus=true`. Set the pool's `SourceArn` to
`arn:aws:ses:us-east-2:000000000000:identity/sender@example.com`.
SES sandbox restrictions still apply to recipients: verify the recipient too,
or use an SES mailbox-simulator address. Identities are not auto-verified.

The actual SQLite executable smoke verified the one-use link, a `DEVELOPER`
pool's captured signup mail, confirmation and password login. Memory/SQLite
regressions additionally preserve unchanged pool state after invalid updates and
distinguish absent resources from repository failures.
Sources: [Cognito email configuration](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_EmailConfigurationType.html),
[CreateUserPool errors](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPool.html),
[SES email identity verification](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_CreateEmailIdentity.html).

The [SES executable capture](../testdata/integration/sesv2_cognito_verified.json)
exercises AWS CLI simple mail, SDK raw/template/bulk
mail, MIME parsing, malformed MIME rejection, sender/sandbox/IAM isolation,
configuration tag conditions, client-independent Cognito verification/reset,
administrative attribute verification, developer-role rollback and a SQLite
restart preserving the captured bytes. Configured CloudTrail management/data
selectors deliver SES records to gzip S3 objects, with resolved identity,
configuration-set and template resources and no body, recipient or code leakage.
It records ten readable messages and ordinary service-linked-role deletion:
an attached developer pool produces a terminal failure with its ARN; after pool
removal and service-time expiry of the issued role session, deletion succeeds.
All owned pools, SES/IAM resources, trail and bucket were removed.
Native `testdata/aws/sesv2/validation.json` records only safe validation failures
and account reads; it is not native successful-send or Cognito-delivery evidence.
`get_account_audit.json` establishes the `ses.amazonaws.com` event source for
the native SES v2 account call. Exact sending audit fields remain only
documentation-calibrated, not a full native sending capture.

Primary contracts: [Cognito email settings](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-email.html),
[recovery priority and expiry](https://docs.aws.amazon.com/cognito/latest/developerguide/managing-users-passwords.html),
[SES CloudTrail](https://docs.aws.amazon.com/ses/latest/dg/logging-using-cloudtrail.html).

### Classic SES and shared sending authority

The generated classic AWS Query frontend and v2 REST frontend share one
`sesv2.Service`, typed memory/SQLC repository, authorization path and capture
scheduler. Cognito continues to consume that owner. There is no second identity,
template, configuration, policy or outgoing-message store. Both frontend
registration orders support classic template creation, v2 replacement and classic
deletion through the generated Go SDK clients.

The [complete inventory](services.json) catalogs all **71** modeled classic
operations: **28 partial**, **43 unimplemented**, none declared complete.
Implemented paths include email verification and identity reads/deletion,
sending-policy CRUD, stored-template lifecycle/rendering, simple/raw/template/bulk
sending, configuration-set lifecycle/sending controls and account sending controls.
Deprecated `VerifyEmailAddress`, `DeleteVerifiedEmailAddress` and
`ListVerifiedEmailAddresses` use the same identity owner; the current native CLI
rejects two of these before sending a request, so those rejections are not native
service evidence.

Email verification captures a real one-use link. Repeating pending verification
invalidates the old link without deleting policies or tags. Sending authorization
policies bind current IAM principals through the existing compiler and retain
their immutable IDs in typed rows. Classic `PutIdentityPolicy` upserts; v2 creation
rejects an existing name and v2 update rejects a missing policy, as observed
natively. Both frontends consume current policy grants/denials, including
same-region cross-account source/feedback identity ARNs and raw authorization
headers. Accepted messages retain the resolved source identity ARN for audit.
Broader resource-policy delegation of identity control APIs is not implemented.

The native [version-value capture](../testdata/aws/ses/classic-iam-version-values.json)
establishes **`ses:ApiVersion=1` for classic and `2` for v2**. These are IAM
condition values, not Smithy API dates: both `2010-12-01` and `2019-09-27`
deny both native frontends. Earlier local-only date-condition assertions did not
establish AWS behavior and have been replaced, without aliases. Captures include
positive unconditional controls, separate classic send actions, and current-role
revocation using the same session; native propagation was observed, not modeled
as a fabricated fixed delay.

[Validation fixtures](../testdata/aws/ses/classic-validation.json) and the two
additional IAM captures retain 251 native service observations plus six separately
identified CLI-only rejections. All fifteen exact-owned resource instances were
deleted and their absence checked. Replay covers missing/duplicate resources,
policy validation/absence and send-error precedence on memory and SQLite.
The reserved invalid sender was never verified natively: these captures do not
prove native successful sending, Internet delivery or exact native sending-audit
field presence.

`scripts/aws/ses_classic_executable_smoke.py` runs the assembled controller and
`scripts/aws/ses_classic_sdk_smoke` generated SDK clients with explicit local
endpoints. Its exercised workflow includes shared resources, verified links,
classic/v2 MIME, BCC privacy and retained envelopes, raw explicit destinations,
partial bulk failure without extra MIME, current IAM/API-version/action controls,
cross-account policy grant/revocation, account/region isolation, Cognito
confirmation/recovery, controller restart and exact resource cleanup.
The [retained executable evidence](../testdata/integration/ses_classic_verified.json)
records 25 readable captures, ten generated-SDK messages across restart, eighteen
unchanged MIME hashes, seven exact-owned resources removed, and two normal zero
controller exits. Counts describe this workflow, not service completeness.
The companion SES v2/Cognito executable proof additionally delivers actual
CloudTrail records to S3. Public classic calls record the classic source/action
through the same transaction as state; audit failure rolls back accepted MIME
on both backends. Native request-ID-correlated classic CloudTrail capture remains
open rather than inferred from local journal results.

Classic messages enforce the documented 10 MiB ceiling; v2 retains its 40 MiB
ceiling. SMTP is still deferred. Unsupported operation families remain explicit:

| Missing owner/behavior | Classic operations |
| --- | --- |
| Actual inbound mail, rule/filter execution and bounce effects | `CloneReceiptRuleSet`; create/delete/list receipt filters and rule sets; create/delete/describe/update receipt rules; `DescribeActiveReceiptRuleSet`, `DescribeReceiptRuleSet`, `ReorderReceiptRuleSet`, `SetActiveReceiptRuleSet`, `SetReceiptRulePosition`, `SendBounce` |
| Custom verification content and consumer | Create/delete/get/list/update custom verification email templates; `SendCustomVerificationEmail` |
| DNS/DKIM and MAIL FROM verification | `VerifyDomainDkim`, `VerifyDomainIdentity`, `GetIdentityDkimAttributes`, `SetIdentityDkimEnabled`, `GetIdentityMailFromDomainAttributes`, `SetIdentityMailFromDomain` |
| Real bounce/complaint notification delivery | `GetIdentityNotificationAttributes`, `SetIdentityFeedbackForwardingEnabled`, `SetIdentityHeadersInNotificationsEnabled`, `SetIdentityNotificationTopic` |
| Event delivery, tracking, delivery policy and reputation consumers | Create/update/delete configuration-set event destinations and tracking options; `PutConfigurationSetDeliveryOptions`, `UpdateConfigurationSetReputationMetricsEnabled` |
| Enforced quotas and actual delivery statistics | `GetSendQuota`, `GetSendStatistics`; captured MIME is not invented SMTP delivery, rejection or complaint statistics |

`DescribeConfigurationSet` rejects requested unsupported attributes rather than
returning fictitious destination/tracking/reputation state. Full Handlebars,
domain identity inheritance, successful native delegated sends, delegated
default-configuration behavior and broader validation/partition conformance
remain open.

Primary contracts:
[classic SES API](https://docs.aws.amazon.com/ses/latest/APIReference/API_Operations.html),
[sending authorization](https://docs.aws.amazon.com/ses/latest/dg/sending-authorization.html),
[IAM API-version conditions](https://docs.aws.amazon.com/ses/latest/dg/control-user-access.html#iam-and-ses-examples-access-specific-ses-api-version)
and [bulk send admission](https://docs.aws.amazon.com/ses/latest/APIReference/API_SendBulkTemplatedEmail.html).


Classic/v2 SES list tokens bind partition/account/region, logical collection and
the classic identity-type filter. Name-key continuation remains valid across
reconstruction and page-size changes; tokens from another account, region or
collection are rejected. Classic and v2 adapters for the same configuration-set
or template collection share that actual owner rather than a duplicate list.

## Passwords, SRP and tokens

- Password authentication and `USER_SRP_AUTH` use the same salted SRP verifier;
  plaintext user passwords are not retained. SRP uses the 3072-bit group,
  SHA-256, Cognito integer padding and actual proof verification, not a simulated
  challenge-to-success transition. Public `USER_PASSWORD_AUTH`, administrative
  `ADMIN_USER_PASSWORD_AUTH`/`ADMIN_NO_SRP_AUTH`, SRP and nonrotating refresh flows
  enforce their client settings and secret-hash requirements.
- Temporary passwords lead to `NEW_PASSWORD_REQUIRED`. Challenges are scoped to
  the pool, client, user and credential generation, expire using service time and
  are consumed on successful completion. Required attributes and password policy
  are enforced before publishing the new credential and session.
- Access and ID tokens are real RS256 JWTs with distinct pool signing keys and
  `kid` values. They carry issuer, audience/client, subject, token-use, expiry,
  authentication and session claims. Client-readable attributes feed ID claims.
  `GET /<pool-id>/.well-known/jwks.json` exposes the two public keys; private keys
  are not part of pool descriptions. The advertised public endpoint determines
  the pool issuer when the pool is created.
- Refresh tokens are random bearer values; storage retains their SHA-256 digests,
  not the token bytes. Both refresh APIs retain the original authentication time
  and absolute refresh expiry. `GetTokensFromRefreshToken` issues a replacement
  when rotation is enabled; legacy refresh requires rotation to be disabled.
- `RevokeToken` invalidates the refresh family and JWTs carrying its original
  `origin_jti`. Global sign-out invalidates all of the user's token origins.
  Retained family metadata attributes rejected refresh attempts without granting
  further refresh access.
  Cognito token-consuming APIs check current user,
  client and session state as well as signature, issuer, token use and expiry.
  Revocation does **not** invalidate an offline JWT signature or remove the
  public key. Applications doing only offline verification must not interpret
  signature validity as proof that Cognito still accepts the token.

The local-only regression `TestCognitoRegionlessEndpointPasswordLogin` covers
unsigned SDK login through a regionless endpoint and SDK login signed with the
existing native-replay SigV4 transport. Explicitly regional requests remain
bound to that Region; a regionless unsigned request resolves the bearer client
ID uniquely within its partition, without default-account or default-Region
fallback. Public `InitiateAuth` is not IAM-authorized: cross-account isolation
means credentials and sessions cannot authenticate a different pool's user,
not that the caller's IAM account must own the app client
([AWS API contract](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html)).

The regression independently checks both JWT signatures with Go's RSA verifier
and keys fetched over HTTP from the served JWKS, and asserts pool/client/user
claims and distinct access/ID signing keys. It checks wrong passwords, another
account's user credentials, missing clients, wrong-client refresh and wrong
Region. Its SQLite reopen path verifies previously issued JWTs against retained
keys, accepts the original access and refresh sessions, and repeats signed login.
These are local behavioral assertions, not new native captures or evidence that
offline signature verification enforces revocation. Run the regression with:

```sh
go test ./integration -run '^TestCognitoRegionlessEndpointPasswordLogin$' -count=1 -v
```

CloudFormation prefix-domain creation recovery is observation-only under the
caller's current `CreateUserPoolDomain` authority. It returns the persisted
result only for the exact private incarnation claim; an authorized lookup of a
foreign or unclaimed domain certifies that this incarnation was not admitted.
It never retries native creation to infer ownership from a duplicate-domain
error. A missing parent or current IAM denial remains a recovery failure rather
than a certificate of nonadmission. The local memory/SQLite regression is
`TestCFNCognitoDomainRecoveryNeverAdoptsForeignDomain`; the stack-level
`TestCloudFormationCognitoGuardLifecycle` requires a conflicting domain create
to reach `ROLLBACK_COMPLETE` without disturbing the original domain.

## Refresh rotation

Essentials clients support rotation, with zero to sixty seconds of retry grace.
Only the current token and one previous token within its fixed grace deadline
are accepted. Retrying the previous token replaces the current child without
extending grace; displaced children and older ancestors raise
`RefreshTokenReuseException`. Reuse rejection does not revoke the valid family.
Historical tokens retain family ownership for revocation, including after restart.

Disabling rotation exposes the current refresh generation's `origin_jti` in
new JWTs; re-enabling restores the original family origin. `event_id` and
`auth_time` remain unchanged. Native `RevokeToken` rejects further refresh and
family-origin JWTs but leaves these generation-origin JWTs usable until expiry
or global sign-out. Even revoking the current child does not invalidate them.
With token revocation disabled and rotation enabled, initial ID tokens include
the origin while initial access tokens omit it; rotated access tokens include it.

Private-client secrets are checked before token/user attribution. Public clients
ignore an extra secret. Lite rejects rotation, explicit legacy refresh conflicts
with it, and enabled clients prevent a pool downgrade to Lite. Unsupported device
tracking and Lambda triggers remain separate configuration boundaries.

The native corpus contains 110 calls and 109 exact-request-ID audit records;
the missing-client request was absent from bounded history lookup. Successful
grace retries and reuse failures carry native string-valued audit flags.
A standalone SQLite executable verified schema 166→167 preservation of three
SDK-issued active/revoked/deleted-user families, rejection at the four-second
grace boundary, displaced-child rejection and absolute refresh expiry at 3600
seconds. Configured CloudTrail write selection delivered refresh success and
reuse denial through EventBridge into SQS with token redaction intact.

Primary contracts: [refresh tokens](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-refresh-token.html)
and [token revocation](https://docs.aws.amazon.com/cognito/latest/developerguide/token-revocation.html).

## Native admission distinctions

The retained AWS admission capture establishes these specific behaviors:

- With `PreventUserExistenceErrors=ENABLED`, an absent user's SRP request returns
  a synthetic `PASSWORD_VERIFIER` challenge. `USERNAME` and `USER_ID_FOR_SRP`
  preserve the requested username in the captured cases. The salt is stable for
  repeated requests and across clients in the same pool, but differs for another
  username. Invalid proofs for absent and real users have the same captured error
  class and HTTP status. Locally, the pool's retained private key derives this
  stable pool/username salt; no synthetic user or usable challenge is persisted.
  This derivation is an implementation choice, not AWS's private algorithm.
- A `NEW_PASSWORD_REQUIRED` session initiated by `AdminInitiateAuth` can be
  completed by public `RespondToAuthChallenge`, and the reverse direction also
  succeeds. A challenge is not bound to the initiating API's public/admin form.
  Administrative completion still requires IAM permission; public completion
  still requires the actual challenge and client/user proof.
- In a pool with email and preferred-username aliases, setting a preferred
  username to an email-shaped alias fails with `InvalidParameterException`.
  Setting it to another user's canonical username fails with
  `AliasExistsException`. The captured rejected updates preserve both users and
  the existing email lookup. Alias namespace validation and ownership are not
  interchangeable error cases.

These observations do not establish every case-folding, alias-transfer or
challenge/error-precedence combination.

## Groups and current token authorization

`group_workflows.json` retains 100 native calls covering all nine group/membership
operations and JWT effects; `cloudtrail_groups.json` matches all 100 calls by
captured AWS response request ID. The fixture replays on memory and SQLite,
including reopening at membership, role-update and deletion boundaries.

- Adding an existing membership and removing an absent membership are idempotent.
  Removing an existing user from a nonexistent group also succeeds; a nonexistent
  user still fails. Verified email aliases resolve to the canonical member.
- Deleting a group removes membership without deleting users. Deleting and
  recreating a username does not restore its former memberships.
- Group names occur in both access and ID tokens; role and preferred-role claims
  occur only in ID tokens in this capture. Refresh observes current membership
  and role settings, not those from the original login.
- The lowest numeric precedence among role-bearing groups selects the preferred
  role. A lower-precedence group without a role does not suppress that choice.
  Equal numeric precedence with different roles omits the preferred role; equal
  precedence with the same role retains it. Unranked groups never select a
  preferred role in the captured cases, including a single unranked group and
  two unranked groups with identical role ARNs.
- Omitted/null update fields and an empty description preserve existing values.
  These no-op updates preserve the modification timestamp. An empty role ARN is
  invalid. Group audit timestamps use RFC3339 rather than the user/client date
  rendering.
- Supplying an identical nonempty description advances the modification
  timestamp; it is not equivalent to omitting the field.
- All three group listing APIs reject `Limit=0` with `InvalidParameterException`,
  despite the shared Smithy shape and published API reference permitting zero.
  The service-owned minimum is therefore one, not a global model override.
- When both username and group are absent, membership add/remove return
  `UserNotFoundException`. A zero-limit membership listing still attributes its
  known user in CloudTrail; the other zero-limit listing failures have no subject.

The group probes use nonexistent role ARNs: they do not establish Identity Pool
credential issuance. All owned pools were deleted and subsequently observed absent.

`group_authority_workflows.json` captures 43 native calls using scoped STS session
policies; all 43 have exact-request-ID-correlated CloudTrail evidence:

- Supplying `RoleArn` to `CreateGroup` or `UpdateGroup` requires `iam:PassRole` on
  that ARN. An explicit session-policy deny prevents the mutation.
- Role authorization precedes duplicate/missing group checks. Resubmitting the
  current role still requires permission; updating only the description does not.
- Neither `iam:PassedToService` nor `iam:AssociatedResourceArn` is available in
  this native admission context. Policies requiring either key to be null permit
  assignment; policies requiring a Cognito service principal or the pool ARN deny
  it. Do not copy another service's role-passing condition context into Cognito.
- The denial audit records `AccessDenied` with null request and response
  parameters, while the API returns `AccessDeniedException`. The verified
  federated caller remains attributable.

The fixture uses real local STS sessions and IAM evaluation on memory and SQLite,
including reopening after rejected and accepted role updates. It does not
substitute a privileged caller for scoped requests.

Lists paginate deterministically by group name or canonical username. Native
ordering is not a contract: replay checks page lengths, cursor transitions and
complete collection contents instead of pinning AWS's private ordering.
Group controls use pool-scoped IAM. Denied and accepted group creation also
flow through configured CloudTrail selection, EventBridge and SQS across restart.
The standalone SQLite smoke independently verifies RSA signatures, restarts with
retained memberships, refreshes into updated role selection, and verifies that
deleting/recreating a user restores neither memberships nor the old refresh family.

## Self-service profiles and deletion

`UpdateUserAttributes`, `DeleteUserAttributes` and `DeleteUser` authorize the
access token, not the request's IAM signing credentials. They use the shared
attribute schema, current app-client permissions, alias checks and user repository.
Email auto-verification queues a code for a changed email address. Unsupported
SMS delivery and verification-before-update settings remain rejected.

The 60-call `profile_workflows.json` capture and all 60 request-ID-correlated
`cloudtrail_profiles.json` events establish these distinctions:

- Default app-client write permissions include custom attributes. Explicit write
  lists restrict updates/deletions and must include pool-required attributes.
  Public writes/deletes of verification flags return `InvalidParameterException`;
  missing client write permission returns `NotAuthorizedException`.
- Duplicate attribute names use the last value, including validation: an invalid
  earlier value does not reject a valid last value. Public and administrative
  writes share this behavior. `birthdate` enforces its schema's ten-character
  length, not an additional date-format parser.
- Immutable and required attributes remain protected. Rejected mixed updates
  do not commit earlier changes. Empty values remove mutable optional attributes;
  deleting an absent optional attribute is idempotent.
- Public signup materializes the unverified email flag; the captured
  administrative creation without an explicit flag leaves it absent. Changing a
  verified email clears verification; deleting it removes the paired flag.
- Self-deletion removes the profile and group memberships, and revokes retained
  refresh families. An old access token observes `UserNotFoundException` after
  deletion, `UserNotConfirmedException` after unconfirmed username recreation,
  then `NotAuthorizedException` after confirmation. Old refresh credentials never
  become valid again. New-user audit attribution is not old-token authorization.
- Public attribute-validation failures retain the bearer-resolved audit subject.
  The captured administrative schema rejection has no subject. Command owners
  choose that boundary explicitly; ordinary user lookup has no audit side effects.

Fixture replay covers memory and SQLite, reopening after profile mutation,
deletion and recreation. A standalone SQLite process independently verified
JWT signatures, restarted with current profile/group state, exercised deletion
and recreation, and delivered five correlated public success/denial outcomes
through configured CloudTrail write selectors, EventBridge and SQS. The actual
165 → 166 startup migration preserved active/revoked families and their behavior.

Primary contracts:
[profile updates](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateUserAttributes.html),
[attribute deletion](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUserAttributes.html)
and [self-deletion](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUser.html).

## Storage and authority

`storage/cognitoidp.Repository` exposes the service-owned typed contract, with
shared-domain memory and SQLC/SQLite adapters. Schema **164** adds separate pool,
client, user, ordered user-attribute, signing-key, challenge and session tables.
Schema **165** adds scoped group fields and indexed membership tables. Group/user
deletion removes memberships; deleting a group does not delete its users.
Schema **166** retains revoked refresh families after user deletion while keeping
client/pool cascades. No deleted user profile or membership is retained.
Schema **167** retains historical token digests, current/previous grace state,
generation origins and the distinction between family and global revocation.
Schema **235** adds user-owned email-code digests and expiry, cascading on user
or pool deletion but surviving app-client deletion. Schema **234** owns SES
identities, templates, configuration sets, tags and durable MIME/capture state.
Schema **260** adds sending-policy documents, bound principal IDs and the resolved
accepted-message source identity ARN, preserving earlier captured bytes.
An actual schema 259→260 executable upgrade retains verified identities,
templates, configuration and MIME, then consumes them through the classic API.
The new shared sending policy and both message captures survive another restart;
three controller exits and exact-owned resource cleanup are verified.
Scalar state has typed columns; nested generated configurations have bounded
configuration columns, not an opaque whole-resource JSON store. Password salts,
verifiers and temporary-password deadlines are separate from public user fields.
Signing material is separate from pool configuration, with separate access/ID
keys. Client secrets and private signing material remain sensitive local database
contents; this is not KMS encryption at rest.

Successful command mutations and their shared journal outcomes commit in the
same transaction. The existing command-attempt boundary rolls back rejected
mutations while retaining the rejection outcome. Pool/client deletion removes
owned authentication state; user deletion removes challenges and revokes families.
Service time governs temporary
passwords, challenges and token acceptance; SQLite retains the keys and refresh
families rather than recreating them on process restart.

Administrative/control APIs use ordinary signed IAM authorization. Generated
public APIs instead use Cognito's client-secret, challenge or user-token
credentials. Public routing does not acquire IAM authority from supplied signing
material. It starts with partition/Region only; the actual app client or verified
token resolves the resource owner for recipient audit scope. Unknown public
clients/tokens with no resolved recipient do not produce an invented account
record. Public audit identity remains anonymous, not the pool owner's IAM caller.

Cognito contributes sanitized management outcomes to the shared event journal
and existing CloudTrail/EventBridge consumers. Passwords, tokens, secrets,
authentication parameters and sensitive user fields are masked. Recipient scope
and native audit projection are separate from authorization; no Cognito-specific
event bus or CloudTrail Lake path is added.

## Retained evidence

Native AWS captures from September 24, 2026 are in `testdata/aws/cognito/`:

| Fixture | Retained evidence |
| --- | --- |
| `login_workflows.json` | Pool/client defaults, signed versus public admission, temporary/permanent passwords, actual SRP login, client secrets, JWT/JWKS verification, refresh and server-side revocation/user-state outcomes. |
| `admission_workflows.json` | Hidden-user SRP comparisons, public/admin new-password challenge crossover and alias collisions with post-rejection reads. Its deliberately invalid SRP signatures are not valid-proof evidence. |
| `cloudtrail_login.json` | Bounded native `LookupEvents` capture correlated to the login probe: 100 resource-identified owned events and one separately retained temporal candidate. |
| `group_workflows.json` | Group CRUD, alias-aware and idempotent membership, pagination, user/group deletion and signed access/ID role-claim transitions. |
| `cloudtrail_groups.json` | 100 owned management events, each uniquely correlated to a captured AWS response request ID; no temporal-only candidates. |
| `group_authority_workflows.json` | Scoped STS session-policy denies, role admission precedence, IAM condition-key availability and post-rejection group reads. |
| `cloudtrail_group_authority.json` | All 43 calls correlated by AWS request ID, including federated caller identity and suppressed IAM-denied request parameters. |
| `credential_workflows.json` | 36 calls covering disable/re-enable, password changes, permanent/temporary administrative resets, challenge completion and app-client deletion; existing tokens remain accepted after a temporary reset. |
| `cloudtrail_credentials.json` | 35 owned events uniquely correlated by AWS request ID; this is not evidence that all 36 calls produced an audit event. |
| `client_access_workflows.json` | Current read-attribute permissions apply to existing access tokens; deleted restricted clients return `ResourceNotFoundException`, including after 65 seconds. |
| `cloudtrail_client_access.json` | 16 owned request-ID-correlated events from bounded history lookup; no captured `ChangePassword` or `GlobalSignOut` events. Missing history is not proof those operations never emit events. |
| `client_retirement_workflows.json` | Paired default/restricted clients in one pool: both reject bearer operations after deletion, including delayed reads; six access/ID JWT projections independently verify signatures and claims. |
| `profile_workflows.json` | 60 calls covering default/restricted attribute writes, final-duplicate validation, schema rejection atomicity, self-deletion and username/token reincarnation. |
| `cloudtrail_profiles.json` | All 60 calls uniquely correlated by AWS request ID, including anonymous public identity, redaction and user-subject attribution on successful/rejected operations. |
| `refresh_rotation_workflows.json` | 110 calls covering rotation, retry replacement, secrets, tier/configuration transitions, origin claims and family/global revocation. |
| `cloudtrail_refresh_rotation.json` | 109 exact-request-ID events; the missing-client request remains an explicit bounded absence. |

`scripts/aws/cognito_login_probe.py --slice` selects `login`, `admission`, `groups`,
`group-authority`, `credentials`, `client-access`, `profile` or `rotation`. All successful authentication results share one
JWT verification/collection path. The probe
uses `pycognito` 2024.5.1's `AWSSRP`, independently of the Go server implementation.
`scripts/aws/cognito_cloudtrail_probe.py` reads native audit history without
creating a trail or executing additional Cognito mutations. Fixtures retain probe
source and redaction details. Each mutation capture records successful deletion
and subsequent absence of its owned pools. Secrets and bearer credentials are
redacted; public JWKS and decoded synthetic-user claims remain evidence.

CloudTrail history is eventual, not proof that every API attempt has an event.
The original login probe did not retain response request IDs. Its audit labels
use one-to-one operation/result/nonsecret-field/time matches; ambiguous events
are not assigned labels, and temporal proximity alone does not establish ownership.
The shared signed transport now returns a typed response with AWS request ID,
and the group capture uses exact request-ID correlation. Bounded collection waits
for captured request IDs as well as operation names: seeing one event per API
does not establish that every request was observed. Missing request IDs remain
explicit when the round/page bound is reached. None of these native fixtures
records trail delivery or CloudTrail Lake behavior.

The captures explicitly selected Lite pools; the rotation probe upgrades its owned
pool to Essentials and uses one synthetic active user. Omitted tier defaults,
cross-account/Region behavior, token-expiry waiting and temporary-password expiry
are not native evidence from these probes. Local SDK workflows separately verify
account/Region isolation, IAM denial and scoped permission, precise access/refresh
expiry, and configured CloudTrail management selection through EventBridge into
an authorized SQS target on both memory and SQLite.

`go test ./integration -run '^TestCognito(Native|Workflow)' -count=1` passes the
native login/admission/audit replays and these local workflows. The redacted
captured SRP proof cannot be replayed; an independent `pycognito` client instead
completed a real SRP login against the standalone SQLite process. That smoke also
exercised signup and administrative confirmation, custom ID-token attributes,
independent RSA verification, process restart with unchanged JWKS, refresh-family
continuity, password changes and revocation without affecting a separate login.
These checks establish the exercised application paths, not complete Cognito.

The credential replay covers the captured reset/suspension sequence through
post-challenge refresh on memory and SQLite, including reopening after the
temporary reset. Existing access and refresh tokens remain accepted after
`AdminSetUserPassword(Permanent=false)` while the user is `FORCE_CHANGE_PASSWORD`;
password login still enforces the temporary-password challenge and expiry.
Disable/re-enable keeps the earlier family revoked.

The paired client-retirement capture also replays on both stores, including
reopening after permission updates and client deletion. `GetUser` applies current
client read permissions to already-issued tokens; default read permissions include
custom attributes. Deleted-client bearer requests return `ResourceNotFoundException`.
Unspecified custom string constraints remain an empty object rather than exposing
invented minimum/maximum fields.

One immediate `GetUser` after default-client deletion succeeded in the credential
capture. A separate paired capture rejected both default and restricted clients
immediately and after 65 seconds with `ResourceNotFoundException`. Propagation or
caching is a possible explanation, not an established guarantee or timing model.
These observations do not justify retaining deleted clients indefinitely.

## Remaining boundaries

SMTP/Internet delivery, SMS invitation/verification/recovery, custom message
templates, MFA, remembered devices,
external federated sign-in, hosted UI, OAuth endpoints/custom domains, Lambda
triggers/custom authentication and signing-key rotation
are deferred. So are advanced security/analytics, imported client secrets,
customer-managed pool keys and remaining modeled operations. Broader
quotas, error precedence, schema/alias conformance and partition behavior remain
incomplete. Unsupported execution operations fail explicitly; configuring OAuth
and identity providers does not synthesize external authentication or OAuth tokens.

SES capture does not implement suppression/contact lists, event destinations,
delivery analytics, DNS/DKIM domain verification, custom MAIL FROM, dedicated IPs
or tenants. Sending-policy authority is shared by classic/v2 actual sends;
broader policy delegation of identity control operations is not implemented.
Stored templates support simple
substitutions and nested object paths, not full Handlebars blocks, helpers or
partials; unsupported syntax is rejected rather than sent unchanged.

App clients persist OAuth flows, scopes, callback/logout URLs, default redirect URI
and enabled identity-provider selection through native Create/Update/Describe and
SQLite reopen. Updates replace omitted mutable settings with their defaults (the
client name and immutable secret remain). OAuth fields require
`AllowedOAuthFlowsUserPoolClient: true`; code/implicit flows require callback URLs,
and client credentials requires a secret and cannot be combined with another flow.
Standard OIDC scopes are supported; custom scopes fail `ScopeDoesNotExistException`
because native resource servers are not implemented. Redirects must be absolute
and fragment-free; HTTP is limited to localhost/loopback addresses. A default
redirect must appear in callback URLs. Federated providers must already exist in
the same user pool, so a CloudFormation client selecting Google must depend on the
provider resource (a literal `"Google"` does not create an implicit dependency).
These rules follow the [AWS CreateUserPoolClient contract](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPoolClient.html).

Intentional `TODO: Comeback` markers currently live in:

- `internal/services/cognitoidp/pools.go`: real triggers, SMS, MFA, devices,
  customer-managed keys and advanced security before admitting active settings.
- `internal/services/cognitoidp/email.go`: selected SMS recovery delivery.
- `internal/services/sesv2/service.go`: remaining SES operation families and
  external delivery owners.
- `internal/services/sesv2/classic.go`: classic inbound/verification-template,
  quota/statistics, tracking/reputation and other unavailable consumers.
- `internal/services/sesv2/classic_identities.go`: DNS/DKIM domains, custom MAIL
  FROM and real SNS feedback notification consumers.
- `internal/services/sesv2/templates.go`: full Handlebars evaluation.

Primary references: [Cognito user-pool API](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/Welcome.html),
[user existence protection](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-managing-errors.html),
[groups and precedence](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-user-groups.html),
[JWT verification](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html)
and [CloudTrail logging](https://docs.aws.amazon.com/cognito/latest/developerguide/logging-using-cloudtrail.html).
